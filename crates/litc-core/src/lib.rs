//! LiTC validation: transactions, one-time WOTS+ spends, and blocks.
//!
//! A LiTC output's `script_pubkey` is simply the 20-byte commitment
//! `HASH160(R)` of the owner's WOTS+ public root `R`. Spending witnesses a
//! `WotsSignature` in the input's `script_sig`. Validation:
//!   1. the referenced UTXO exists (rejects double spends, incl. intra-block),
//!   2. the WOTS+ signature verifies against the transaction sighash and the
//!      committed `HASH160(R)`,
//!   3. the commitment has not been spent before (WOTS+ one-time use).

use litc_primitives::{
    sha256d, to_bytes, wots, Amount, Block, BlockHeader, Hash32, OutPoint, Transaction, TxIn, TxOut,
};
use litc_pow::EPOCH_BLOCKS;
use litc_store::SpendStore;
use std::collections::HashSet;

/// Block subsidy (newly minted value per coinbase, in satoshis of 1e-8 LIT).
pub const SUBSIDY: Amount = Amount(50 * 100_000_000);

/// A coinbase output cannot be spent until this many blocks have been mined on
/// top of the block that created it. Prevents a deep reorg from instantly
/// re-spending freshly minted coin, and keeps the coinbase UTXO set bounded.
pub const COINBASE_MATURITY: u64 = 100;

/// A block timestamp may not be more than this far in the future (seconds).
const MAX_FUTURE_SKEW: u64 = 2 * 60 * 60;

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The message a WOTS+ signature covers. The signed input's `script_sig` is
/// replaced by its prevout `script_pubkey` (so the signature commits to the
/// prevout, not to itself); other inputs are zeroed. Then SHA-256d.
pub fn sighash(tx: &Transaction, input_index: usize, prev_script: &[u8]) -> [u8; 32] {
    let mut copy = tx.clone();
    for (i, inp) in copy.inputs.iter_mut().enumerate() {
        inp.script_sig = if i == input_index {
            prev_script.to_vec()
        } else {
            Vec::new()
        };
    }
    sha256d(&to_bytes(&copy)).0
}

/// Pure validation of a single *non-coinbase* transaction. Verifies, against
/// the current UTXO set:
///   1. every referenced UTXO exists (rejects double spends),
///   2. the WOTS+ signature verifies against the sighash and `HASH160(R)`,
///   3. the commitment has not been spent before (WOTS+ one-time use),
///   4. `sum(outputs) <= sum(inputs)` (no value creation / inflation).
///
/// This function has **no side effects**: it never spends UTXOs or burns keys.
/// Application happens separately in `apply_tx`, only after the whole block
/// has passed validation. Returns the total input value (for fee accounting).
/// A coinbase (no inputs) is rejected here — coinbase rules are enforced at
/// the block level in `validate_block_value`.
///
/// `spend_height` is the height of the block that will contain this
/// transaction; it is used to enforce the coinbase-maturity rule.
pub fn validate_tx<S: SpendStore>(
    tx: &Transaction,
    store: &S,
    spend_height: u64,
) -> Result<u64, String> {
    if tx.inputs.is_empty() {
        return Err("coinbase must be validated at block level".into());
    }
    let mut sum_in: u64 = 0;
    for (idx, inp) in tx.inputs.iter().enumerate() {
        let prev = store
            .utxo(&inp.prevout)
            .ok_or_else(|| "input not found or already spent".to_string())?
            .clone();
        if prev.script_pubkey.len() != 20 {
            return Err("bad script_pubkey: need 20-byte HASH160(R)".into());
        }
        let commit: [u8; 20] = prev.script_pubkey[..20].try_into().unwrap();
        if store.is_burnt(&commit) {
            return Err("address already spent (WOTS+ one-time)".into());
        }
        // Coinbase maturity: a coinbase output may only be spent after
        // `COINBASE_MATURITY` blocks have been mined on top of its block.
        if let Some(h) = store.coinbase_height(&inp.prevout) {
            if spend_height < h + COINBASE_MATURITY {
                return Err("coinbase output is not mature yet".into());
            }
        }
        let witness = wots::decode_witness(&inp.script_sig)
            .map_err(|_| "cannot decode WOTS+ witness".to_string())?;
        let msg = sighash(tx, idx, &prev.script_pubkey);
        if !witness.verify(&msg, &commit) {
            return Err("WOTS+ signature invalid".into());
        }
        sum_in = sum_in
            .checked_add(prev.value.0)
            .ok_or_else(|| "input value overflow".to_string())?;
    }
    let sum_out: u64 = tx.outputs.iter().map(|o| o.value.0).sum();
    if sum_out > sum_in {
        return Err("transaction creates value (inflation)".into());
    }
    Ok(sum_in)
}

/// Validate a block header against chain context (pure, no UTXO access):
///   - height must be exactly `parent.height + 1`,
///   - the parent must exist,
///   - the `epoch_seed` must match the parent (or `H(prev_block)` at an epoch
///     boundary),
///   - the timestamp must advance past the parent and not be far in the future.
pub fn validate_block_header<S: SpendStore>(
    block: &Block,
    store: &S,
) -> Result<(), String> {
    let height = block.header.height;
    if height == 0 {
        // Genesis: no parent to check.
        return Ok(());
    }
    let parent = store
        .get_block(&block.header.prev_block)
        .ok_or_else(|| "prev_block not found".to_string())?;
    if parent.header.height + 1 != height {
        return Err("height does not follow parent".into());
    }
    let expected_seed: [u8; 32] = if height.is_multiple_of(EPOCH_BLOCKS) {
        sha256d(&block.header.prev_block.0).0
    } else {
        parent.header.epoch_seed.0
    };
    if expected_seed != block.header.epoch_seed.0 {
        return Err("bad epoch_seed".into());
    }
    if block.header.timestamp <= parent.header.timestamp {
        return Err("timestamp does not advance".into());
    }
    if block.header.timestamp > now_secs() + MAX_FUTURE_SKEW {
        return Err("timestamp too far in the future".into());
    }
    Ok(())
}

/// Block-level value validation (pure). Enforces:
///   - exactly one coinbase, and it is the first transaction,
///   - no intra-block double spend,
///   - `sum(outputs) <= sum(inputs)` for every spend (delegated to `validate_tx`),
///   - coinbase value `<= SUBSIDY + total_fees`.
pub fn validate_block_value<S: SpendStore>(
    block: &Block,
    store: &S,
) -> Result<(), String> {
    let mut spent_in_block: HashSet<OutPoint> = HashSet::new();
    let mut sum_fees: u64 = 0;
    let mut seen_coinbase = false;
    for (i, tx) in block.txs.iter().enumerate() {
        if tx.inputs.is_empty() {
            if i != 0 {
                return Err("coinbase must be the first transaction".into());
            }
            if seen_coinbase {
                return Err("more than one coinbase".into());
            }
            seen_coinbase = true;
            continue;
        }
        for inp in &tx.inputs {
            if spent_in_block.contains(&inp.prevout) {
                return Err("intra-block double spend".into());
            }
        }
        let sum_in = validate_tx(tx, store, block.header.height)?;
        let sum_out: u64 = tx.outputs.iter().map(|o| o.value.0).sum();
        let fee = sum_in - sum_out;
        sum_fees = sum_fees
            .checked_add(fee)
            .ok_or_else(|| "fee overflow".to_string())?;
        for inp in &tx.inputs {
            spent_in_block.insert(inp.prevout.clone());
        }
    }
    if let Some(cb) = block.txs.first() {
        if cb.inputs.is_empty() {
            let out: u64 = cb.outputs.iter().map(|o| o.value.0).sum();
            let max_allowed = SUBSIDY
                .0
                .checked_add(sum_fees)
                .ok_or_else(|| "subsidy overflow".to_string())?;
            if out > max_allowed {
                return Err("coinbase value exceeds subsidy + fees".into());
            }
        }
    }
    Ok(())
}

/// Apply a *validated* transaction to the store, spending its inputs and
/// burning the spent keys. Callers must have already passed `validate_tx`
/// (which guarantees every input exists and is unburnt), so this cannot fail
/// under normal conditions.
fn apply_tx<S: SpendStore>(
    tx: &Transaction,
    store: &mut S,
    height: u64,
    is_coinbase: bool,
) -> Result<(), String> {
    for inp in &tx.inputs {
        let prev = store
            .utxo(&inp.prevout)
            .ok_or_else(|| "input not found or already spent".to_string())?
            .clone();
        if prev.script_pubkey.len() != 20 {
            return Err("bad script_pubkey: need 20-byte HASH160(R)".into());
        }
        let commit: [u8; 20] = prev.script_pubkey[..20].try_into().unwrap();
        store.spend_utxo(&inp.prevout)?;
        store.mark_spent_once(&commit)?;
    }
    for (i, out) in tx.outputs.iter().enumerate() {
        let op = OutPoint {
            txid: tx.txid(),
            index: i as u32,
        };
        store.add_utxo(op.clone(), out.clone(), tx.ephemeral.clone());
        if is_coinbase {
            store.mark_coinbase(&op, height);
        }
    }
    Ok(())
}

/// SHA-256d of the block header with the `nonce` field zeroed. This is the
/// PoW `challenge` that binds the work to the block's content.
pub fn block_challenge(header: &BlockHeader) -> [u8; 32] {
    let mut b = to_bytes(header);
    b.truncate(b.len() - 8); // drop the trailing nonce (last field)
    sha256d(&b).0
}

/// Verify the block's Proof-of-Work: rebuild the epoch scratchpad from
/// `epoch_seed`, recompute the digest over the challenge, and check it meets
/// `target`.
pub fn check_pow(header: &BlockHeader, target: &[u8; 32]) -> bool {
    let challenge = block_challenge(header);
    let scratch = litc_pow::prepare_epoch(&header.epoch_seed.0);
    let digest = litc_pow::mine(&scratch, header.nonce, &challenge);
    litc_pow::meets_target(&digest, target)
}

/// Validate a block, then apply it: check PoW and merkle root, validate every
/// transaction, spend inputs, add outputs, record the block and advance tip.
pub fn connect_block<S: SpendStore>(
    block: &Block,
    store: &mut S,
    target: &[u8; 32],
) -> Result<(), String> {
    if !validate_block_pow_merkle(block, target) {
        return Err("proof-of-work / merkle invalid".into());
    }
    apply_block(store, block)?;
    store.set_tip(block.block_hash(), block.header.height);
    Ok(())
}

/// Check only the Proof-of-Work and merkle root of a block (no UTXO access).
/// Used by the node before committing a block to the active chain.
pub fn validate_block_pow_merkle(block: &Block, target: &[u8; 32]) -> bool {
    if !check_pow(&block.header, target) {
        return false;
    }
    let mut computed = block.clone();
    computed.recompute_merkle();
    computed.header.merkle_root == block.header.merkle_root
}

/// Apply a block to the store, recording per-block `UndoData` (via
/// `begin_block`/`end_block`) so it can later be rolled back on a reorg.
/// Performs **all** validation (header + value/inflation) *before* mutating
/// the UTXO set, so a failing block leaves the store untouched and its
/// `UndoData` is never even created. Does not check PoW (callers validate PoW
/// once, at first sight, via `remember_pow`) and does not set the tip — chain
/// selection is the node's job.
pub fn apply_block<S: SpendStore>(store: &mut S, block: &Block) -> Result<(), String> {
    // Pure validation first — no side effects, so a rejected block cannot
    // partially corrupt the UTXO set.
    validate_block_header(block, store)?;
    validate_block_value(block, store)?;
    store.begin_block(block.block_hash());
    for (i, tx) in block.txs.iter().enumerate() {
        apply_tx(tx, store, block.header.height, i == 0)?;
    }
    store.end_block();
    store.put_block(block)?;
    Ok(())
}

/// Lowest common ancestor of two blocks (the shared block nearest `b`'s tip),
/// walking parents up from both. Returns `None` only if neither reaches a
/// shared root.
pub fn common_ancestor<S: SpendStore>(store: &S, mut a: Hash32, mut b: Hash32) -> Option<Hash32> {
    let mut seen = HashSet::new();
    loop {
        seen.insert(a);
        a = match store.parent_of(&a) {
            Some(p) => p,
            None => break,
        };
    }
    loop {
        if seen.contains(&b) {
            return Some(b);
        }
        b = match store.parent_of(&b) {
            Some(p) => p,
            None => break,
        };
    }
    None
}

/// Path of block hashes from the child *after* `ancestor` up to `from`, in
/// ascending height order — the branch to connect during a reorg.
pub fn path_to<S: SpendStore>(
    store: &S,
    mut from: Hash32,
    ancestor: Option<Hash32>,
) -> Vec<Hash32> {
    let mut v = Vec::new();
    while Some(from) != ancestor {
        v.push(from);
        from = match store.parent_of(&from) {
            Some(p) => p,
            None => break,
        };
    }
    v.reverse();
    v
}

/// Reorganise the active chain to the one with the most cumulative work.
/// Rolls back the current tip to the common ancestor, then connects the new
/// branch. UTXO changes are reversed via each block's `UndoData`. The caller
/// is responsible for having validated PoW and recorded each block's `work`.
pub fn reorganize<S: SpendStore>(store: &mut S) {
    let new_tip = match store.best_tip_by_work() {
        Some(h) => h,
        None => return,
    };
    let cur = match store.tip() {
        Some(h) => h,
        None => {
            // Nothing applied yet: just connect the best chain from genesis.
            connect_branch(store, new_tip, None);
            return;
        }
    };
    if cur == new_tip {
        return;
    }
    let ancestor = common_ancestor(store, cur, new_tip);
    // Disconnect the current chain down to (not including) the ancestor.
    let mut h = cur;
    while Some(h) != ancestor {
        store.disconnect(&h);
        h = match store.parent_of(&h) {
            Some(p) => p,
            None => break,
        };
    }
    connect_branch(store, new_tip, ancestor);
}

/// Connect every block on the path from `ancestor`'s child up to `tip`.
fn connect_branch<S: SpendStore>(store: &mut S, tip: Hash32, ancestor: Option<Hash32>) {
    for bhash in path_to(store, tip, ancestor) {
        if !store.is_applied(&bhash) {
            if let Some(block) = store.get_block(&bhash) {
                if let Err(e) = apply_block(store, &block) {
                    eprintln!("reorg: cannot apply {}: {e}", hex(&bhash.0[..4]));
                    // Abort: the tip is only advanced once the *entire* branch
                    // has applied successfully, so the store never points at a
                    // chain with missing/partially-applied blocks.
                    return;
                }
            }
        }
        store.mark_applied(bhash);
    }
    let hgt = store.height_of(&tip).unwrap_or(0);
    store.set_tip(tip, hgt);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Helpers for building transactions (used by wallet/miner and tests)
// ---------------------------------------------------------------------------

/// A coinbase with a single output to `commit` (20-byte HASH160(R)).
pub fn coinbase(commit: [u8; 20], value: Amount, height: u64) -> (Block, OutPoint) {
    let tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            value,
            script_pubkey: commit.to_vec(),
            ephemeral: vec![],
        }],
        ephemeral: vec![],
        lock_time: 0,
    };
    let op = OutPoint {
        txid: tx.txid(),
        index: 0,
    };
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            prev_block: Hash32([0u8; 32]),
            merkle_root: Hash32([0u8; 32]),
            timestamp: 0,
            height,
            epoch_seed: Hash32([0u8; 32]),
            nonce: 0,
        },
        txs: vec![tx],
    };
    block.recompute_merkle();
    (block, op)
}

/// Build a signed spend of `prev` (owned by `kp`) paying `value` to `to_commit`.
pub fn spend(
    kp: &wots::WotsKeypair,
    prev: OutPoint,
    prev_script: &[u8],
    value: Amount,
    to_commit: [u8; 20],
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev,
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: to_commit.to_vec(),
            ephemeral: vec![],
        }],
        ephemeral: vec![],
        lock_time: 0,
    };
    let msg = sighash(&tx, 0, prev_script);
    tx.inputs[0].script_sig = wots::encode_witness(&kp.sign(&msg));
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use litc_store::{BlockStore, ChainStore, MemoryStore, UtxoStore};

    /// Trivial target: any PoW passes. Used by validation tests (which focus
    /// on signatures/merkle/one-time, not difficulty).
    const EASY: [u8; 32] = [0xff; 32];

    /// Build a single-output coinbase paying `commit`.
    fn cb(commit: [u8; 20], value: Amount) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value,
                script_pubkey: commit.to_vec(),
                ephemeral: vec![],
            }],
            ephemeral: vec![],
            lock_time: 0,
        }
    }

    /// A reorg must switch the active tip to the heaviest known chain and roll
    /// the UTXO set back/forward accordingly. Chain B (heavier) overtakes
    /// the already-applied chain A.
    #[test]
    fn reorg_to_heavier_chain() {
        let mut store = MemoryStore::new();

        // Genesis (height 0), applied.
        let (g, _) = coinbase([1u8; 20], Amount(50 * 100_000_000), 0);
        store.put_block(&g).unwrap();
        store.set_work(g.block_hash(), 10);
        apply_block(&mut store, &g).unwrap();
        store.mark_applied(g.block_hash());
        store.set_tip(g.block_hash(), 0);

        // Chain A: A1, A2 — applied, total work 30.
        let a1 = block(
            g.block_hash(),
            1,
            vec![cb([2u8; 20], Amount(50 * 100_000_000))],
        );
        let a2 = block(
            a1.block_hash(),
            2,
            vec![cb([3u8; 20], Amount(50 * 100_000_000))],
        );
        for b in [&a1, &a2] {
            store.put_block(b).unwrap();
            apply_block(&mut store, b).unwrap();
            store.mark_applied(b.block_hash());
            store.set_work(b.block_hash(), 10 * (b.header.height as u128));
        }
        store.set_tip(a2.block_hash(), 2);
        assert_eq!(store.iter_utxos().len(), 3); // g + a1 + a2

        // Chain B: B1, B2, B3 — not yet applied, but heavier (work 90).
        let b1 = block(
            g.block_hash(),
            1,
            vec![cb([4u8; 20], Amount(50 * 100_000_000))],
        );
        let b2 = block(
            b1.block_hash(),
            2,
            vec![cb([5u8; 20], Amount(50 * 100_000_000))],
        );
        let b3 = block(
            b2.block_hash(),
            3,
            vec![cb([6u8; 20], Amount(50 * 100_000_000))],
        );
        for b in [&b1, &b2, &b3] {
            store.put_block(b).unwrap();
            store.set_work(b.block_hash(), 30 * (b.header.height as u128));
        }

        // Heaviest chain wins.
        reorganize(&mut store);
        assert_eq!(store.tip(), Some(b3.block_hash()));
        assert!(store.is_applied(&b3.block_hash()));
        assert!(!store.is_applied(&a2.block_hash()));
        // UTXO set reflects chain B: g + b1 + b2 + b3 = 4 coinbases.
        assert_eq!(store.iter_utxos().len(), 4);
        let bal: u64 = store.iter_utxos().iter().map(|(_, o, _)| o.value.0).sum();
        assert_eq!(bal, 4 * 50 * 100_000_000);

        // A weaker fork must NOT trigger a reorg.
        let c1 = block(
            g.block_hash(),
            1,
            vec![cb([7u8; 20], Amount(50 * 100_000_000))],
        );
        store.put_block(&c1).unwrap();
        store.set_work(c1.block_hash(), 1); // tiny work
        reorganize(&mut store);
        assert_eq!(store.tip(), Some(b3.block_hash()));
    }

    /// Build a block with a correct merkle root.
    fn block(prev: Hash32, height: u64, txs: Vec<Transaction>) -> Block {
        let mut b = Block {
            header: BlockHeader {
                version: 1,
                prev_block: prev,
                merkle_root: Hash32([0u8; 32]),
                timestamp: height,
                height,
                epoch_seed: Hash32([0u8; 32]),
                nonce: 0,
            },
            txs,
        };
        b.recompute_merkle();
        b
    }

    /// Apply `n` coinbase-only blocks on top of `prev`, advancing the chain to
    /// height `n`. Uses `apply_block` (header + value validation, no PoW) so the
    /// suite stays fast; used to mature coinbase outputs before spending them.
    fn extend(store: &mut MemoryStore, mut prev: Hash32, n: u64) -> Hash32 {
        for h in 1..=n {
            let b = block(
                prev,
                h,
                vec![cb([h as u8; 20], Amount(50 * 100_000_000))],
            );
            apply_block(store, &b).unwrap();
            prev = b.block_hash();
        }
        prev
    }

    #[test]
    fn coinbase_then_spend_ok() {
        let kp = wots::WotsKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_root_hash160();
        let (blk, op) = coinbase(commit, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        apply_block(&mut store, &blk).unwrap();

        // Mature the genesis coinbase (created at height 0).
        let tip = extend(&mut store, blk.block_hash(), COINBASE_MATURITY);

        let kp2 = wots::WotsKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_root_hash160();
        let tx = spend(&kp, op, &commit, Amount(49 * 100_000_000), to);
        let spend_block = block(tip, COINBASE_MATURITY + 1, vec![tx]);
        apply_block(&mut store, &spend_block).unwrap();
        assert!(store.burnt().is_burnt(&commit));
    }

    #[test]
    fn coinbase_immature_spend_rejected() {
        let kp = wots::WotsKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_root_hash160();
        let (blk, op) = coinbase(commit, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        apply_block(&mut store, &blk).unwrap();
        // Spend at height 1: the genesis coinbase (height 0) is not mature.
        let tip = extend(&mut store, blk.block_hash(), 1);
        let kp2 = wots::WotsKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_root_hash160();
        let tx = spend(&kp, op, &commit, Amount(49 * 100_000_000), to);
        let spend_block = block(tip, 2, vec![tx]);
        // `apply_block` validates the block, which rejects the immature spend.
        assert!(apply_block(&mut store, &spend_block).is_err());
    }

    #[test]
    fn one_time_reuse_rejected() {
        let kp = wots::WotsKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_root_hash160();
        let (blk, op) = coinbase(commit, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        apply_block(&mut store, &blk).unwrap();

        // Mature the genesis coinbase before spending it.
        let tip = extend(&mut store, blk.block_hash(), COINBASE_MATURITY);
        let kp2 = wots::WotsKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_root_hash160();
        // First spend of the address (burns `commit`).
        let first = spend(&kp, op.clone(), &commit, Amount(49 * 100_000_000), to);
        apply_block(
            &mut store,
            &block(tip, COINBASE_MATURITY + 1, vec![first]),
        )
        .unwrap();
        assert!(store.burnt().is_burnt(&commit));

        // In a fresh store, spend the same address once, then try to spend a
        // second UTXO at the same commitment with the same key.
        let mut store2 = MemoryStore::new();
        apply_block(&mut store2, &blk).unwrap();
        let tip2 = extend(&mut store2, blk.block_hash(), COINBASE_MATURITY);
        let first2 = spend(&kp, op.clone(), &commit, Amount(49 * 100_000_000), to);
        apply_block(
            &mut store2,
            &block(tip2, COINBASE_MATURITY + 1, vec![first2]),
        )
        .unwrap();

        store2.add_utxo(
            OutPoint {
                txid: Hash32([9u8; 32]),
                index: 0,
            },
            TxOut {
                value: Amount(50 * 100_000_000),
                script_pubkey: commit.to_vec(),
                ephemeral: vec![],
            },
            vec![],
        );
        let bad_tx = spend(
            &kp,
            OutPoint {
                txid: Hash32([9u8; 32]),
                index: 0,
            },
            &commit,
            Amount(49 * 100_000_000),
            to,
        );
        assert!(validate_tx(&bad_tx, &store2, 1_000_000).is_err());
    }

    #[test]
    fn bad_signature_rejected() {
        let kp = wots::WotsKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_root_hash160();
        let (blk, op) = coinbase(commit, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        let rogue = wots::WotsKeypair::derive(&[0x99u8; 32], 0);
        let to = rogue.pubkey_root_hash160();
        let mut tx = spend(&rogue, op, &commit, Amount(49 * 100_000_000), to);
        let msg = sighash(&tx, 0, &commit);
        tx.inputs[0].script_sig = wots::encode_witness(&rogue.sign(&msg));
        let b = block(blk.block_hash(), 1, vec![tx]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());
    }

    #[test]
    fn merkle_mismatch_rejected() {
        let kp = wots::WotsKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_root_hash160();
        let (mut blk, _) = coinbase(commit, Amount(50 * 100_000_000), 0);
        blk.header.merkle_root = Hash32([7u8; 32]); // wrong
        let mut store = MemoryStore::new();
        assert!(connect_block(&blk, &mut store, &EASY).is_err());
    }

    /// Helper: a signed spend of `prev` paying `value` to `to`, with a valid
    /// WOTS+ signature but an arbitrary output value (so inflation tests can
    /// over-pay).
    fn signed_spend(
        kp: &wots::WotsKeypair,
        prev: OutPoint,
        prev_commit: &[u8; 20],
        value: Amount,
        to: [u8; 20],
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: prev,
                script_sig: vec![],
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: to.to_vec(),
                ephemeral: vec![],
            }],
            ephemeral: vec![],
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, prev_commit);
        tx.inputs[0].script_sig = wots::encode_witness(&kp.sign(&msg));
        tx
    }

    /// CRITICAL FIX #1: a spend whose outputs exceed its inputs must be rejected
    /// (no value creation / infinite inflation).
    #[test]
    fn inflation_via_outputs_rejected() {
        let kp = wots::WotsKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_root_hash160();
        let (blk, op) = coinbase(commit, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        let kp2 = wots::WotsKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_root_hash160();
        // Pay out 51 LIT while only owning 50 LIT.
        let tx = signed_spend(&kp, op.clone(), &commit, Amount(51 * 100_000_000), to);
        let b = block(blk.block_hash(), 1, vec![tx]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());
    }

    /// CRITICAL FIX #1: a coinbase may mint at most SUBSIDY (+ fees). Minting
    /// more is rejected.
    #[test]
    fn inflated_coinbase_rejected() {
        let (blk, _) = coinbase([1u8; 20], Amount(60 * 100_000_000), 0); // > SUBSIDY
        let mut store = MemoryStore::new();
        assert!(connect_block(&blk, &mut store, &EASY).is_err());
    }

    /// A block may contain exactly one coinbase, and it must be first.
    #[test]
    fn two_coinbases_rejected() {
        let (g, _) = coinbase([0u8; 20], Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&g, &mut store, &EASY).unwrap();
        let cb1 = cb([1u8; 20], Amount(50 * 100_000_000));
        let cb2 = cb([2u8; 20], Amount(50 * 100_000_000));
        let b = block(g.block_hash(), 1, vec![cb1, cb2]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());
    }

    /// CRITICAL FIX #2: an invalid transaction in a block must not partially
    /// mutate the UTXO set. After a rejected block the store is unchanged and
    /// the tip stays where it was.
    #[test]
    fn partial_apply_rolls_back() {
        let kp = wots::WotsKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_root_hash160();
        let (blk, op) = coinbase(commit, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();
        let before = store.iter_utxos().len();

        let kp2 = wots::WotsKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_root_hash160();
        // Tx 0: valid spend of `op` (would consume it on apply).
        let good = signed_spend(&kp, op.clone(), &commit, Amount(49 * 100_000_000), to);
        // Tx 1: a coinbase that is not first -> rejected at block validation.
        let bad = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value: Amount(999),
                script_pubkey: to.to_vec(),
                ephemeral: vec![],
            }],
            ephemeral: vec![],
            lock_time: 0,
        };
        let b = block(blk.block_hash(), 1, vec![good, bad]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());

        // Nothing changed: `op` still unspent, count and tip unchanged.
        assert_eq!(store.iter_utxos().len(), before);
        assert!(store.utxo(&op).is_some());
        assert_eq!(store.tip(), Some(blk.block_hash()));
    }

    /// CRITICAL FIX #1: spending the same UTXO twice inside one block is a
    /// double spend and must be rejected.
    #[test]
    fn intra_block_double_spend_rejected() {
        let kp = wots::WotsKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_root_hash160();
        let (blk, op) = coinbase(commit, Amount(50 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        let kp2 = wots::WotsKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_root_hash160();
        let a = signed_spend(&kp, op.clone(), &commit, Amount(10 * 100_000_000), to);
        let b_tx = signed_spend(&kp, op.clone(), &commit, Amount(10 * 100_000_000), to);
        let b = block(blk.block_hash(), 1, vec![a, b_tx]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());
    }
}
