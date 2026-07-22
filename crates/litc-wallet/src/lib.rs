//! LiTC wallet: stateless, deterministic address derivation from a master
//! seed.
//!
//! Every address is a fresh ML-DSA-2 key pair derived as
//! `MlDsaKeypair::derive(master, index)`. The wallet keeps **no state** — from
//! the master seed it regenerates every key pair, so restoring from the seed
//! is just rescanning the chain forward. Change always goes to a fresh address,
//! so the transaction graph is never linkable by address reuse.

use litc_core::sighash;
use litc_primitives::{mldsa, Amount, SignatureScheme, Transaction, TxIn, TxOut};
use litc_store::UtxoStore;

/// A wallet backed by a single 32-byte master seed.
pub struct Wallet {
    master: [u8; 32],
}

impl Wallet {
    pub fn new(master: [u8; 32]) -> Self {
        Wallet { master }
    }

    /// The ML-DSA-2 key pair at `index`.
    pub fn keypair_at(&self, index: u32) -> mldsa::MlDsaKeypair {
        mldsa::MlDsaKeypair::derive(&self.master, index)
    }

    /// The 20-byte commitment `HASH160(pk)` for the address at `index`.
    pub fn commitment_at(&self, index: u32) -> [u8; 20] {
        self.keypair_at(index).pubkey_hash160()
    }

    /// The bech32m address at `index`.
    pub fn address_at(&self, index: u32, version: u8) -> String {
        self.keypair_at(index).address(version)
    }

    /// Scan forward from index 0 and return the first unused address index,
    /// trusting it only after `gap` consecutive unused addresses (gap limit).
    /// An address counts as used if it has a UTXO.
    pub fn next_unused_index<S: UtxoStore>(&self, store: &S, gap: usize) -> u32 {
        let mut first_unused: Option<u32> = None;
        let mut consecutive = 0u32;
        let mut idx = 0u32;
        loop {
            let commit = self.commitment_at(idx);
            let used = store.find_by_commit(&commit).is_some();
            if used {
                first_unused = None;
                consecutive = 0;
            } else {
                if first_unused.is_none() {
                    first_unused = Some(idx);
                }
                consecutive += 1;
                if consecutive as usize >= gap {
                    return first_unused.unwrap();
                }
            }
            idx += 1;
        }
    }

    /// Build a signed spend of this wallet's address `from_index`, paying
    /// `value` to `to_commit` and sending the change to a fresh address
    /// (`from_index + 1`). The remainder must cover `value`.
    pub fn spend_from<S: UtxoStore>(
        &self,
        store: &S,
        from_index: u32,
        to_commit: [u8; 20],
        value: Amount,
    ) -> Result<Transaction, String> {
        let kp = self.keypair_at(from_index);
        let commit = kp.pubkey_hash160();
        let op = store
            .find_by_commit(&commit)
            .ok_or_else(|| "no UTXO at this address".to_string())?;
        let prev = store
            .utxo(&op)
            .ok_or_else(|| "UTXO already spent".to_string())?;
        let total = prev.value.0;
        if value.0 > total {
            return Err("insufficient funds".into());
        }
        let change = total - value.0;
        let change_commit = self.commitment_at(from_index + 1);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: op,
                script_sig: vec![],
                scheme: SignatureScheme::Mldsa2,
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![
                TxOut {
                    value,
                    script_pubkey: to_commit.to_vec(),
                },
                TxOut {
                    value: Amount(change),
                    script_pubkey: change_commit.to_vec(),
                },
            ],
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, &prev.script_pubkey);
        let pk = kp.public_key_bytes();
        let sig = kp.sign(&msg);
        let mut script_sig = Vec::with_capacity(mldsa::PK_LEN + mldsa::SIG_LEN);
        script_sig.extend_from_slice(&pk);
        script_sig.extend_from_slice(&sig);
        tx.inputs[0].script_sig = script_sig;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litc_core::{apply_block, coinbase, COINBASE_MATURITY};
    use litc_primitives::{Block, BlockHeader, Hash32};
    use litc_store::{BlockStore, ChainStore, MemoryStore};

    #[test]
    fn derivation_deterministic_and_distinct() {
        let w1 = Wallet::new([0x11u8; 32]);
        let w2 = Wallet::new([0x11u8; 32]);
        assert_eq!(
            w1.address_at(0, mldsa::MAINNET_VERSION),
            w2.address_at(0, mldsa::MAINNET_VERSION)
        );
        assert_ne!(
            w1.address_at(0, mldsa::MAINNET_VERSION),
            w1.address_at(1, mldsa::MAINNET_VERSION)
        );
    }

    #[test]
    fn spend_with_change() {
        let w = Wallet::new([0xABu8; 32]);
        let commit0 = w.commitment_at(0);
        let (blk, _op) = coinbase(commit0, Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        apply_block_raw(&mut store, &blk);
        for _ in 0..COINBASE_MATURITY {
            apply_block_tip(&mut store, vec![]);
        }

        let recip = Wallet::new([0xCDu8; 32]);
        let to = recip.commitment_at(0);

        let tx = w
            .spend_from(&store, 0, to, Amount(4 * 100_000_000))
            .unwrap();
        apply_block_tip(&mut store, vec![tx]);

        // Index 0 consumed, change at index 1. With ML-DSA-2 keys are reusable,
        // so index 0 is available again. With gap=1, returns 0.
        let idx = w.next_unused_index(&store, 1);
        assert_eq!(idx, 0);
        // With gap=2: idx=0 unused, idx=1 occupied (change), idx=2 unused
        // → consecutive=1, not enough. idx=3 unused → consecutive=2 ≥ gap → return 2.
        let idx2 = w.next_unused_index(&store, 2);
        assert_eq!(idx2, 2);
    }

    /// Build a block that continues the current chain tip.
    fn block_with(store: &MemoryStore, txs: Vec<Transaction>) -> Block {
        let tip = store.tip().expect("no tip yet");
        let prev = store.get_block(&tip).expect("prev block missing");
        let height = prev.header.height + 1;
        let timestamp = prev.header.timestamp + 1;
        let epoch_seed = prev.header.epoch_seed;
        let mut b = Block {
            header: BlockHeader {
                version: 1,
                prev_block: tip,
                merkle_root: Hash32([0u8; 32]),
                state_root: Hash32([0u8; 32]),
                timestamp,
                height,
                epoch_seed,
                nonce: 0,
            },
            txs,
        };
        b.recompute_merkle();
        b
    }

    fn apply_block_raw(store: &mut MemoryStore, b: &Block) {
        apply_block(
            store,
            b,
            litc_primitives::chainparams::ChainParams::testnet().halving_interval,
        )
        .unwrap();
        store.set_tip(b.block_hash(), b.header.height);
    }

    fn apply_block_tip(store: &mut MemoryStore, txs: Vec<Transaction>) {
        let b = block_with(store, txs);
        apply_block_raw(store, &b);
    }
}
