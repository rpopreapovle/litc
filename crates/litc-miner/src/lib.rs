//! LiTC mining: build a block and find a PoW nonce via LiteHash.
//!
//! The miner is backend-agnostic through `MinerBackend`; `CpuMiner` is the
//! always-available pure-Rust implementation. A GPU backend (wgpu) can
//! implement the same trait later behind a feature flag.

use litc_pow::{meets_target, mine, prepare_epoch};
use litc_primitives::{sha256d, to_bytes, Amount, Block, BlockHeader, Hash32, Transaction, TxOut};

/// Everything needed to assemble a candidate block (except the nonce).
pub struct BlockTemplate {
    pub prev_block: Hash32,
    pub height: u64,
    pub timestamp: u64,
    /// Epoch seed for the 512 MB scratchpad (see `docs/pow.md`).
    pub epoch_seed: Hash32,
    /// Coinbase value (block subsidy + fees).
    pub coinbase_value: Amount,
    /// ScriptPubKey for the coinbase output (payment to miner's address).
    pub coinbase_script: Vec<u8>,
    /// Non-coinbase transactions to include.
    pub txs: Vec<Transaction>,
    /// Root committing to the live consensus state after this block is applied
    /// (see `docs/state.md`). Set by the node before mining so the PoW binds
    /// the work to the resulting state.
    pub state_root: Hash32,
}

/// A mining backend.
pub trait MinerBackend {
    /// Search for a nonce making the block's PoW meet `target`. Returns the
    /// full valid block, or `None` if the search space is exhausted.
    fn mine_block(&self, template: &BlockTemplate, target: &[u8; 32]) -> Option<Block>;
}

/// CPU mining backend (pure Rust, no extra dependencies).
pub struct CpuMiner;

impl MinerBackend for CpuMiner {
    fn mine_block(&self, t: &BlockTemplate, target: &[u8; 32]) -> Option<Block> {
        let coinbase = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value: t.coinbase_value,
                script_pubkey: t.coinbase_script.clone(),
            }],
            lock_time: 0,
        };
        let mut txs = vec![coinbase];
        txs.extend(t.txs.iter().cloned());

        let mut block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: t.prev_block,
                merkle_root: Hash32([0u8; 32]),
                state_root: t.state_root,
                timestamp: t.timestamp,
                height: t.height,
                epoch_seed: t.epoch_seed,
                nonce: 0,
            },
            txs,
        };
        block.recompute_merkle();

        // PoW challenge: SHA-256d of the header with the nonce zeroed.
        let mut hb = to_bytes(&block.header);
        hb.truncate(hb.len() - 8);
        let challenge = sha256d(&hb).0;

        let scratch = prepare_epoch(&block.header.epoch_seed.0);

        let mut nonce: u64 = 0;
        loop {
            let digest = mine(&scratch, nonce, &challenge);
            if meets_target(&digest, target) {
                block.header.nonce = nonce;
                return Some(block);
            }
            nonce = nonce.wrapping_add(1);
            if nonce == 0 {
                return None; // wrapped: search space exhausted
            }
        }
    }
}

/// Build the candidate block from a template without mining (nonce = 0). Used
/// by the node to compute the template's `state_root` before mining.
pub fn assemble_block(t: &BlockTemplate) -> Block {
    // Coinbase script = commitment (20 bytes) || height (8 bytes LE).
    // The height suffix makes each coinbase output unique, so each block
    // produces a different txid even when paying the same address.
    let mut coinbase_script = Vec::with_capacity(28);
    coinbase_script.extend_from_slice(&t.coinbase_script);
    coinbase_script.extend_from_slice(&t.height.to_le_bytes());
    let coinbase = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            value: t.coinbase_value,
            script_pubkey: coinbase_script,
        }],
        lock_time: 0,
    };
    let mut txs = vec![coinbase];
    txs.extend(t.txs.iter().cloned());
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            prev_block: t.prev_block,
            merkle_root: Hash32([0u8; 32]),
            state_root: t.state_root,
            timestamp: t.timestamp,
            height: t.height,
            epoch_seed: t.epoch_seed,
            nonce: 0,
        },
        txs,
    };
    block.recompute_merkle();
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mines_a_valid_block() {
        let t = BlockTemplate {
            prev_block: Hash32([1u8; 32]),
            height: 1,
            timestamp: 1_700_000_000,
            epoch_seed: Hash32([2u8; 32]),
            coinbase_value: Amount(5 * 100_000_000),
            coinbase_script: vec![0xaa; 20],
            txs: vec![],
            state_root: Hash32([0u8; 32]),
        };
        // ~4 bits of work: fast even in debug builds.
        let target = [0x0f; 32];
        let block = CpuMiner
            .mine_block(&t, &target)
            .expect("should find a nonce");
        assert!(litc_core_check(&block, &target));
    }

    // Local PoW check mirroring litc-core to avoid a core dependency here.
    fn litc_core_check(block: &Block, target: &[u8; 32]) -> bool {
        let mut hb = to_bytes(&block.header);
        hb.truncate(hb.len() - 8);
        let challenge = sha256d(&hb).0;
        let scratch = prepare_epoch(&block.header.epoch_seed.0);
        let digest = mine(&scratch, block.header.nonce, &challenge);
        meets_target(&digest, target)
    }
}
