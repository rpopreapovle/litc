//! LiTC wallet: stateless, deterministic address derivation from a master
//! seed (see `docs/wots.md`).
//!
//! Every address is a fresh WOTS+ key pair derived as
//! `WotsKeypair::derive(master, index)`. The wallet keeps **no state** — from
//! the master seed it regenerates every key pair, so restoring from the seed
//! is just rescanning the chain forward. Change always goes to a fresh address,
//! so the transaction graph is never linkable by address reuse.

use litc_core::sighash;
use litc_keystore::{KeyStore, StealthKey};
use litc_primitives::{kem, stealth, wots, Amount, Transaction, TxIn, TxOut};
use litc_store::{SpendStore, UtxoStore};

/// A wallet backed by a single 32-byte master seed.
pub struct Wallet {
    master: [u8; 32],
}

/// A stealth output owned by this wallet, as found by `scan_chain`.
pub struct OwnedStealth {
    pub outpoint: litc_primitives::OutPoint,
    pub keypair: wots::WotsKeypair,
    pub value: Amount,
}

impl Wallet {
    pub fn new(master: [u8; 32]) -> Self {
        Wallet { master }
    }

    /// The WOTS+ key pair at `index`.
    pub fn keypair_at(&self, index: u32) -> wots::WotsKeypair {
        wots::WotsKeypair::derive(&self.master, index)
    }

    /// The 20-byte commitment `HASH160(R)` for the address at `index`.
    pub fn commitment_at(&self, index: u32) -> [u8; 20] {
        self.keypair_at(index).pubkey_root_hash160()
    }

    /// The base58 address at `index`.
    pub fn address_at(&self, index: u32, version: u8) -> String {
        self.keypair_at(index).address(version)
    }

    /// Hard one-time-key guard (type-level + DB). A WOTS+ key must never sign
    /// two different messages: doing so leaks the secret and lets an attacker
    /// forge spends. Refuse if the commitment is already burnt on-chain *or*
    /// has already been signed by this wallet (even for an unconfirmed tx).
    fn ensure_one_time<S: SpendStore>(
        &self,
        ks: &dyn KeyStore,
        store: &S,
        commit: &[u8; 20],
    ) -> Result<(), String> {
        if store.is_burnt(commit) {
            return Err(
                "WOTS+ key already spent on-chain — one-time keys must never be reused".into(),
            );
        }
        let used = ks.load_used().map_err(|e| format!("keystore: {e}"))?;
        if used.iter().any(|c| c == commit) {
            return Err(
                "WOTS+ key already used by this wallet — one-time signatures must never be reused"
                    .into(),
            );
        }
        Ok(())
    }

    /// Record `commit` as spent in the wallet's persisted used set so it can
    /// never be signed again.
    fn mark_one_time(&self, ks: &dyn KeyStore, commit: &[u8; 20]) -> Result<(), String> {
        let mut used = ks.load_used().map_err(|e| format!("keystore: {e}"))?;
        if !used.iter().any(|c| c == commit) {
            used.push(*commit);
            ks.save_used(&used).map_err(|e| format!("keystore: {e}"))?;
        }
        Ok(())
    }

    /// Scan forward from index 0 and return the first unused address index,
    /// trusting it only after `gap` consecutive unused addresses (gap limit).
    /// An address counts as used if it has a UTXO or its key is already burnt.
    pub fn next_unused_index<S: UtxoStore + SpendStore>(&self, store: &S, gap: usize) -> u32 {
        let mut first_unused: Option<u32> = None;
        let mut consecutive = 0u32;
        let mut idx = 0u32;
        loop {
            let commit = self.commitment_at(idx);
            let used = store.find_by_commit(&commit).is_some() || store.is_burnt(&commit);
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
    ///
    /// Enforces the WOTS+ one-time rule: `from_index`'s key must not already be
    /// burnt on-chain nor previously signed by this wallet (even unconfirmed).
    /// Reusing a WOTS+ key leaks the secret.
    pub fn spend_from<S: UtxoStore + SpendStore>(
        &self,
        store: &S,
        ks: &dyn KeyStore,
        from_index: u32,
        to_commit: [u8; 20],
        value: Amount,
    ) -> Result<Transaction, String> {
        let kp = self.keypair_at(from_index);
        let commit = kp.pubkey_root_hash160();
        self.ensure_one_time(ks, store, &commit)?;
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
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![
                TxOut {
                    value,
                    script_pubkey: to_commit.to_vec(),
                    ephemeral: vec![],
                },
                TxOut {
                    value: Amount(change),
                    script_pubkey: change_commit.to_vec(),
                    ephemeral: vec![],
                },
            ],
            ephemeral: vec![],
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, &prev.script_pubkey);
        tx.inputs[0].script_sig = wots::encode_witness(&kp.sign(&msg));
        self.mark_one_time(ks, &commit)?;
        Ok(tx)
    }

    // -----------------------------------------------------------------------
    // Reusable stealth addresses (ML-KEM + one-time WOTS+)
    //
    // The user-facing address is a fixed ML-KEM encapsulation public key.
    // Sending wraps a fresh one-time WOTS+ key (locked into the output's
    // script) and attaches the KEM ciphertext; the recipient scans the chain,
    // decapsulates, and recovers the WOTS+ spend key. See docs/stealth.md.
    // -----------------------------------------------------------------------

    /// The KEM (encapsulation public key, decapsulation seed) derived
    /// deterministically from the master seed. The seed is the only secret;
    /// the public key is recomputed from it, so the wallet stays stateless.
    pub fn kem_keypair(&self) -> ([u8; kem::KEM_PK_LEN], [u8; kem::KEM_SK_LEN]) {
        kem::kem_keypair_from_seed(&self.master)
    }

    /// The reusable (multi-use) stealth address for this wallet.
    pub fn stealth_address(&self, version: u8) -> String {
        let (pk, _) = self.kem_keypair();
        stealth::stealth_address(&pk, version)
    }

    /// Spend a legacy WOTS address `from_index`, paying `value` to a reusable
    /// stealth `recipient` address. Change returns to a fresh legacy address.
    ///
    /// Enforces the WOTS+ one-time rule (see `spend_from`).
    pub fn send_stealth<S: UtxoStore + SpendStore>(
        &self,
        store: &S,
        ks: &dyn KeyStore,
        from_index: u32,
        recipient: &str,
        value: Amount,
    ) -> Result<Transaction, String> {
        let kem_pk = stealth::parse_stealth_address(recipient)
            .ok_or_else(|| "not a stealth address".to_string())?;
        let kp = self.keypair_at(from_index);
        let commit = kp.pubkey_root_hash160();
        self.ensure_one_time(ks, store, &commit)?;
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

        // Encapsulate once; the shared secret funds a one-time WOTS+ key at
        // index 0. The ciphertext is attached to the transaction (tx-level
        // `ephemeral`), so multiple stealth outputs would share one ciphertext.
        let (ss, ct) = kem::kem_encaps(&kem_pk);
        let stealth_out = TxOut {
            value,
            script_pubkey: stealth::stealth_script(&ss, 0).to_vec(),
            ephemeral: vec![],
        };
        let mut outputs = vec![stealth_out];
        if change > 0 {
            outputs.push(TxOut {
                value: Amount(change),
                script_pubkey: change_commit.to_vec(),
                ephemeral: vec![],
            });
        }

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: op,
                script_sig: vec![],
                sequence: 0xFFFF_FFFF,
            }],
            outputs,
            ephemeral: ct.to_vec(),
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, &prev.script_pubkey);
        tx.inputs[0].script_sig = wots::encode_witness(&kp.sign(&msg));
        self.mark_one_time(ks, &commit)?;
        Ok(tx)
    }

    /// Scan the chain for payments made to this wallet's reusable address.
    /// For every unspent output carrying a KEM ciphertext, decapsulate it and
    /// check whether the derived one-time WOTS+ key matches the output's
    /// commitment. Matches are persisted to the keystore and returned.
    pub fn scan_chain<S: UtxoStore>(
        &self,
        store: &S,
        ks: &dyn KeyStore,
    ) -> Result<Vec<OwnedStealth>, String> {
        let (_, sk) = self.kem_keypair();
        let mut known = ks.load_stealth().unwrap_or_default();
        let mut found = Vec::new();
        for (op, out, ephemeral) in store.iter_utxos() {
            if ephemeral.is_empty() {
                continue;
            }
            let kp = match stealth::recover_stealth_keypair_at(&sk, &ephemeral, op.index) {
                Some(kp) => kp,
                None => continue,
            };
            if kp.pubkey_root_hash160().as_slice() != out.script_pubkey.as_slice() {
                continue;
            }
            let commit = kp.pubkey_root_hash160();
            if known.iter().any(|k| k.commit == commit) {
                found.push(OwnedStealth {
                    outpoint: op,
                    keypair: kp,
                    value: out.value,
                });
                continue;
            }
            known.push(StealthKey {
                commit,
                sk_seed: kp.sk_seed,
                pk_seed: kp.pk_seed,
                r: kp.r,
            });
            found.push(OwnedStealth {
                outpoint: op,
                keypair: kp,
                value: out.value,
            });
        }
        ks.save_stealth(&known)?;
        Ok(found)
    }

    /// Spend a stealth output previously found (and persisted) by `scan_chain`.
    /// `to_commit` is the 20-byte commitment of the recipient's address.
    ///
    /// Enforces the WOTS+ one-time rule: the recovered stealth key's commitment
    /// must not already be burnt nor previously signed.
    pub fn spend_stealth<S: UtxoStore + SpendStore>(
        &self,
        store: &S,
        ks: &dyn KeyStore,
        outpoint: litc_primitives::OutPoint,
        to_commit: [u8; 20],
    ) -> Result<Transaction, String> {
        let prev = store
            .utxo(&outpoint)
            .ok_or_else(|| "stealth UTXO already spent".to_string())?;
        let commit: [u8; 20] = prev
            .script_pubkey
            .clone()
            .try_into()
            .map_err(|_| "bad script_pubkey for stealth output".to_string())?;
        self.ensure_one_time(ks, store, &commit)?;
        let entry = ks
            .load_stealth()?
            .into_iter()
            .find(|k| k.commit.to_vec() == commit)
            .ok_or_else(|| "no stealth key for this output".to_string())?;
        let kp = wots::WotsKeypair::new(entry.sk_seed, entry.pk_seed, entry.r);

        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: outpoint,
                script_sig: vec![],
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![TxOut {
                value: prev.value,
                script_pubkey: to_commit.to_vec(),
                ephemeral: vec![],
            }],
            ephemeral: vec![],
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, &prev.script_pubkey);
        tx.inputs[0].script_sig = wots::encode_witness(&kp.sign(&msg));
        self.mark_one_time(ks, &commit)?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litc_core::{coinbase, connect_block};
    use litc_keystore::FileKeyStore;
    use litc_primitives::{Block, BlockHeader, Hash32};
    use litc_store::{BlockStore, ChainStore, MemoryStore};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const EASY: [u8; 32] = [0xff; 32];
    static TMP: AtomicUsize = AtomicUsize::new(0);

    fn tmp_ks() -> FileKeyStore {
        let n = TMP.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("litc_stealth_test_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("stealth"));
        FileKeyStore::new(path)
    }

    #[test]
    fn derivation_deterministic_and_distinct() {
        let w1 = Wallet::new([0x11u8; 32]);
        let w2 = Wallet::new([0x11u8; 32]);
        assert_eq!(w1.address_at(0, 0x30), w2.address_at(0, 0x30));
        assert_ne!(w1.address_at(0, 0x30), w1.address_at(1, 0x30));
    }

    #[test]
    fn spend_with_change_and_scan() {
        let w = Wallet::new([0xABu8; 32]);
        let ks = tmp_ks();
        let commit0 = w.commitment_at(0);
        let (blk, _op) = coinbase(commit0, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        // Fresh recipient.
        let recip = Wallet::new([0xCDu8; 32]);
        let to = recip.commitment_at(0);

        let tx = w
            .spend_from(&store, &ks, 0, to, Amount(10 * 100_000_000))
            .unwrap();
        let spend_block = block_with(&store, vec![tx]);
        connect_block(&spend_block, &mut store, &EASY).unwrap();

        // Change lands at index 1 (used); index 0 is burnt. Next free = 2.
        let idx = w.next_unused_index(&store, 1);
        assert_eq!(idx, 2);

        // The wallet now refuses to reuse index 0 (key already spent).
        assert!(w.spend_from(&store, &ks, 0, to, Amount(1)).is_err());
    }

    #[test]
    fn stealth_address_send_scan_spend() {
        let a = Wallet::new([0xABu8; 32]);
        let b = Wallet::new([0xCDu8; 32]);
        let b_ks = tmp_ks();
        let a_ks = tmp_ks();

        // A receives a coinbase at legacy address 0.
        let commit0 = a.commitment_at(0);
        let (blk, _op) = coinbase(commit0, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        // A pays B's reusable stealth address.
        let b_addr = b.stealth_address(stealth::STEALTH_VERSION_MAINNET);
        let tx = a
            .send_stealth(&store, &a_ks, 0, &b_addr, Amount(10 * 100_000_000))
            .unwrap();
        connect_block(&block_with(&store, vec![tx]), &mut store, &EASY).unwrap();

        // B scans the chain and finds exactly one owned output.
        let owned = b.scan_chain(&store, &b_ks).unwrap();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].value, Amount(10 * 100_000_000));

        // B spends it back to one of A's addresses.
        let to = a.commitment_at(1);
        let spend_tx = b
            .spend_stealth(&store, &b_ks, owned[0].outpoint.clone(), to)
            .unwrap();
        connect_block(&block_with(&store, vec![spend_tx]), &mut store, &EASY).unwrap();

        // The one-time stealth key is now burnt.
        assert!(store
            .burnt()
            .is_burnt(&owned[0].keypair.pubkey_root_hash160()));

        // Re-scanning must not duplicate the (now spent) output.
        let owned2 = b.scan_chain(&store, &b_ks).unwrap();
        assert_eq!(owned2.len(), 0);
    }

    /// Build a block that continues the current chain tip (valid prev_block,
    /// height, timestamp and epoch_seed) so header validation passes.
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
}
