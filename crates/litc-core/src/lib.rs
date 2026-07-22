//! LiTC validation: transactions and blocks.
//!
//! A LiTC output's `script_pubkey` is the 20-byte commitment
//! `HASH160(pk)` of the owner's ML-DSA-2 public key. Spending witnesses the
//! full public key + signature in the input's `script_sig`. Validation:
//!   1. the referenced UTXO exists (rejects double spends, incl. intra-block),
//!   2. the ML-DSA-2 signature verifies against the transaction sighash and the
//!      committed `HASH160(pk)`.

use litc_pow::EPOCH_BLOCKS;
use litc_primitives::chainparams::ChainParams;
use litc_primitives::{
    hash160, mldsa, sha256d, to_bytes, Amount, Block, BlockHeader, Hash32, OutPoint,
    SignatureScheme, Transaction, TxIn, TxOut,
};
use litc_store::state::{OverlayState, StateStore, UtxoEntry};
use litc_store::SpendStore;
use std::collections::HashSet;

/// Consensus state abstraction (trait + in-memory implementations). Lives in
/// `litc-store` to avoid a dependency cycle; re-exported here for convenience.
pub use litc_store::state;

/// Initial block reward, before any halving. 5 LIT.
pub const BASE_SUBSIDY: Amount = Amount(5 * 100_000_000);
/// Blocks between subsidy halvings (~4 years at 15 s blocks).
pub const HALVING_INTERVAL: u64 = 8_400_000;
/// Block reward at `height`: `BASE_SUBSIDY` right-shifted by the halving epoch.
/// Halves every `HALVING_INTERVAL` blocks; once the epoch exceeds the bit-width
/// of the subsidy it reaches 0, so total issuance converges to
/// `BASE_SUBSIDY * HALVING_INTERVAL * 2 = 84,000,000 LIT` (the supply cap) and no
/// separate cap check is needed.
pub fn block_subsidy(height: u64) -> Amount {
    block_subsidy_with(height, HALVING_INTERVAL)
}

/// Block reward at `height` for a network with the given `halving_interval`.
/// Testnet compresses mainnet's 8,400,000-block interval to 10,000 so emission
/// is observable quickly; the geometric-sum supply cap still holds (the total
/// issued converges to `BASE_SUBSIDY * halving_interval * 2`).
pub fn block_subsidy_with(height: u64, halving_interval: u64) -> Amount {
    let epoch = height / halving_interval;
    if epoch >= 64 {
        return Amount(0);
    }
    Amount(BASE_SUBSIDY.0 >> epoch)
}

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

/// The message a signature covers. The signed input's `script_sig` is
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
///   2. the ML-DSA-2 signature verifies against the sighash and `HASH160(pk)`,
///   3. `sum(outputs) <= sum(inputs)` (no value creation / inflation).
///
/// This function has **no side effects**: it never spends UTXOs or burns keys.
/// Application happens separately in `apply_tx`, only after the whole block
/// has passed validation. Returns the total input value (for fee accounting).
/// A coinbase (no inputs) is rejected here — coinbase rules are enforced at
/// the block level in `validate_block_value`.
///
/// `spend_height` is the height of the block that will contain this
/// transaction; it is used to enforce the coinbase-maturity rule.
pub fn validate_tx<S: StateStore>(
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
            .get_utxo(&inp.prevout)
            .ok_or_else(|| "input not found or already spent".to_string())?;
        if prev.output.script_pubkey.len() != 20 {
            return Err("bad script_pubkey: need 20-byte HASH160(pk)".into());
        }
        let commit: [u8; 20] = prev.output.script_pubkey[..20].try_into().unwrap();
        // Coinbase maturity: a coinbase output may only be spent after
        // `COINBASE_MATURITY` blocks have been mined on top of its block.
        if let Some(h) = prev.coinbase_height {
            if spend_height < h + COINBASE_MATURITY {
                return Err("coinbase output is not mature yet".into());
            }
        }
        let msg = sighash(tx, idx, &prev.output.script_pubkey);
        match inp.scheme {
            SignatureScheme::Mldsa2 => {
                // script_sig = pk (1312 bytes) || sig (2420 bytes)
                if inp.script_sig.len() != mldsa::PK_LEN + mldsa::SIG_LEN {
                    return Err("bad ML-DSA-2 witness length".into());
                }
                let mut pk = [0u8; mldsa::PK_LEN];
                pk.copy_from_slice(&inp.script_sig[..mldsa::PK_LEN]);
                if hash160(&pk) != commit {
                    return Err("ML-DSA-2 public key does not match commitment".into());
                }
                let sig_bytes = &inp.script_sig[mldsa::PK_LEN..];
                if !mldsa::MlDsaKeypair::verify(&pk, &msg, sig_bytes) {
                    return Err("ML-DSA-2 signature invalid".into());
                }
            }
            SignatureScheme::Unknown => {
                return Err("unknown signature scheme".into());
            }
            _ => {
                // Reserved1..3: recognized but not yet active.
                return Err("reserved signature scheme not yet active".into());
            }
        }
        sum_in = sum_in
            .checked_add(prev.output.value.0)
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
pub fn validate_block_header<S: SpendStore>(block: &Block, store: &S) -> Result<(), String> {
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

/// Enforce a checkpoint for `block`, if its height is a configured checkpoint.
/// A checkpoint irreversibly pins a (height, hash) pair: any block at that
/// height whose hash differs is rejected, which finalizes history at and below
/// the checkpoint and bounds the trust placed in a fast-sync snapshot (see
/// `docs/state.md`). With an empty checkpoint list (e.g. a brand-new testnet)
/// this is a no-op.
pub fn validate_checkpoint(block: &Block, params: &ChainParams) -> Result<(), String> {
    if let Some(expected) = params.checkpoint_hash(block.header.height) {
        if block.block_hash() != expected {
            return Err(format!(
                "checkpoint mismatch at height {}: block hash does not match the pinned checkpoint",
                block.header.height
            ));
        }
    }
    Ok(())
}

/// Block-level value validation (pure). Enforces:
///   - exactly one coinbase, and it is the first transaction,
///   - no intra-block double spend,
///   - `sum(outputs) <= sum(inputs)` for every spend (delegated to `validate_tx`),
///   - coinbase value `<= block_subsidy(height) + total_fees`.
pub fn validate_block_value<S: StateStore>(block: &Block, store: &S) -> Result<(), String> {
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
            let max_allowed = block_subsidy(block.header.height)
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

/// Apply a *validated* transaction to the store, spending its inputs.
/// Callers must have already passed `validate_tx` (which guarantees every
/// input exists), so this cannot fail under normal conditions.
fn apply_tx<S: StateStore>(
    tx: &Transaction,
    store: &mut S,
    height: u64,
    is_coinbase: bool,
) -> Result<(), String> {
    for inp in &tx.inputs {
        store.remove_utxo(&inp.prevout);
    }
    for (i, out) in tx.outputs.iter().enumerate() {
        let op = OutPoint {
            txid: tx.txid(),
            index: i as u32,
        };
        store.put_utxo(
            op.clone(),
            UtxoEntry {
                output: TxOut {
                    value: out.value,
                    script_pubkey: out.script_pubkey.clone(),
                },
                coinbase_height: if is_coinbase { Some(height) } else { None },
            },
        );
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
pub fn connect_block<S: SpendStore + StateStore>(
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
pub fn apply_block<S: SpendStore + StateStore>(store: &mut S, block: &Block) -> Result<(), String> {
    // Pure validation first — no side effects, so a rejected block cannot
    // partially corrupt the UTXO set.
    validate_block_header(block, store)?;
    validate_block_value(block, store)?;

    // State-root check (read-only via an overlay; the base is left untouched on
    // a mismatch, so no rollback is needed). A zero `state_root` means "not set"
    // (legacy/test blocks) and is accepted without verification.
    if block.header.state_root != Hash32([0u8; 32]) {
        let mut ov = OverlayState::new(store);
        for tx in block.txs.iter() {
            apply_tx(tx, &mut ov, block.header.height, tx.inputs.is_empty())?;
        }
        if ov.root() != block.header.state_root.0 {
            return Err("state root mismatch".into());
        }
        // `ov` is dropped here; the base store remains unmodified.
    }

    store.begin_block(block.block_hash());
    for tx in block.txs.iter() {
        apply_tx(tx, store, block.header.height, tx.inputs.is_empty())?;
    }
    store.end_block();
    store.put_block(block)?;
    Ok(())
}

/// Compute the `state_root` that results from applying `block` to the current
/// state, without mutating it. The block template's `state_root` (and the mined
/// header's) is set to this value before mining, so the PoW binds the work to
/// the resulting state and a bootstrapping node can verify it trustlessly.
pub fn block_state_root<S: SpendStore + StateStore>(
    store: &mut S,
    block: &Block,
) -> Result<[u8; 32], String> {
    let mut ov = OverlayState::new(store);
    for tx in block.txs.iter() {
        apply_tx(tx, &mut ov, block.header.height, tx.inputs.is_empty())?;
    }
    Ok(ov.root())
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
pub fn reorganize<S: SpendStore + StateStore>(store: &mut S) {
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
fn connect_branch<S: SpendStore + StateStore>(
    store: &mut S,
    tip: Hash32,
    ancestor: Option<Hash32>,
) {
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

/// A coinbase with a single output to `commit` (20-byte HASH160(pk)).
pub fn coinbase(commit: [u8; 20], value: Amount, height: u64) -> (Block, OutPoint) {
    let tx = Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![TxOut {
            value,
            script_pubkey: commit.to_vec(),
        }],
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
            state_root: Hash32([0u8; 32]),
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
    kp: &mldsa::MlDsaKeypair,
    prev: OutPoint,
    prev_script: &[u8],
    value: Amount,
    to_commit: [u8; 20],
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxIn {
            prevout: prev,
            scheme: SignatureScheme::Mldsa2,
            script_sig: vec![],
            sequence: 0xFFFF_FFFF,
        }],
        outputs: vec![TxOut {
            value,
            script_pubkey: to_commit.to_vec(),
        }],
        lock_time: 0,
    };
    let msg = sighash(&tx, 0, prev_script);
    let pk = kp.public_key_bytes();
    let sig = kp.sign(&msg);
    let mut script_sig = Vec::with_capacity(mldsa::PK_LEN + mldsa::SIG_LEN);
    script_sig.extend_from_slice(&pk);
    script_sig.extend_from_slice(&sig);
    tx.inputs[0].script_sig = script_sig;
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
            }],
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
        let (g, _) = coinbase([1u8; 20], Amount(5 * 100_000_000), 0);
        store.put_block(&g).unwrap();
        store.set_work(g.block_hash(), 10);
        apply_block(&mut store, &g).unwrap();
        store.mark_applied(g.block_hash());
        store.set_tip(g.block_hash(), 0);

        // Chain A: A1, A2 — applied, total work 30.
        let a1 = block(
            g.block_hash(),
            1,
            vec![cb([2u8; 20], Amount(5 * 100_000_000))],
        );
        let a2 = block(
            a1.block_hash(),
            2,
            vec![cb([3u8; 20], Amount(5 * 100_000_000))],
        );
        for b in [&a1, &a2] {
            store.put_block(b).unwrap();
            apply_block(&mut store, b).unwrap();
            store.mark_applied(b.block_hash());
            store.set_work(b.block_hash(), 10 * (b.header.height as u128));
        }
        store.set_tip(a2.block_hash(), 2);
        assert_eq!(litc_store::UtxoStore::iter_utxos(&store).len(), 3); // g + a1 + a2

        // Chain B: B1, B2, B3 — not yet applied, but heavier (work 90).
        let b1 = block(
            g.block_hash(),
            1,
            vec![cb([4u8; 20], Amount(5 * 100_000_000))],
        );
        let b2 = block(
            b1.block_hash(),
            2,
            vec![cb([5u8; 20], Amount(5 * 100_000_000))],
        );
        let b3 = block(
            b2.block_hash(),
            3,
            vec![cb([6u8; 20], Amount(5 * 100_000_000))],
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
        assert_eq!(litc_store::UtxoStore::iter_utxos(&store).len(), 4);
        let bal: u64 = litc_store::UtxoStore::iter_utxos(&store)
            .iter()
            .map(|(_, o)| o.value.0)
            .sum();
        assert_eq!(bal, 4 * 5 * 100_000_000);

        // A weaker fork must NOT trigger a reorg.
        let c1 = block(
            g.block_hash(),
            1,
            vec![cb([7u8; 20], Amount(5 * 100_000_000))],
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
                state_root: Hash32([0u8; 32]),
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
            let b = block(prev, h, vec![cb([h as u8; 20], Amount(5 * 100_000_000))]);
            apply_block(store, &b).unwrap();
            prev = b.block_hash();
        }
        prev
    }

    #[test]
    fn coinbase_then_spend_ok() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let (blk, op) = coinbase(commit, Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        apply_block(&mut store, &blk).unwrap();

        // Mature the genesis coinbase (created at height 0).
        let tip = extend(&mut store, blk.block_hash(), COINBASE_MATURITY);

        let kp2 = mldsa::MlDsaKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_hash160();
        let tx = spend(&kp, op, &commit, Amount(4 * 100_000_000), to);
        let spend_block = block(tip, COINBASE_MATURITY + 1, vec![tx]);
        apply_block(&mut store, &spend_block).unwrap();
    }

    #[test]
    fn coinbase_immature_spend_rejected() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let (blk, op) = coinbase(commit, Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        apply_block(&mut store, &blk).unwrap();
        // Spend at height 1: the genesis coinbase (height 0) is not mature.
        let tip = extend(&mut store, blk.block_hash(), 1);
        let kp2 = mldsa::MlDsaKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_hash160();
        let tx = spend(&kp, op, &commit, Amount(4 * 100_000_000), to);
        let spend_block = block(tip, 2, vec![tx]);
        // `apply_block` validates the block, which rejects the immature spend.
        assert!(apply_block(&mut store, &spend_block).is_err());
    }

    #[test]
    fn bad_signature_rejected() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let (blk, op) = coinbase(commit, Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        let rogue = mldsa::MlDsaKeypair::derive(&[0x99u8; 32], 0);
        let to = rogue.pubkey_hash160();
        let mut tx = spend(&rogue, op, &commit, Amount(4 * 100_000_000), to);
        let msg = sighash(&tx, 0, &commit);
        let pk = rogue.public_key_bytes();
        let sig = rogue.sign(&msg);
        let mut script_sig = Vec::with_capacity(mldsa::PK_LEN + mldsa::SIG_LEN);
        script_sig.extend_from_slice(&pk);
        script_sig.extend_from_slice(&sig);
        tx.inputs[0].script_sig = script_sig;
        let b = block(blk.block_hash(), 1, vec![tx]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());
    }

    #[test]
    fn merkle_mismatch_rejected() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let (mut blk, _) = coinbase(commit, Amount(5 * 100_000_000), 0);
        blk.header.merkle_root = Hash32([7u8; 32]); // wrong
        let mut store = MemoryStore::new();
        assert!(connect_block(&blk, &mut store, &EASY).is_err());
    }

    /// CRITICAL FIX #5 (StateRoot): a block whose `state_root` does not match the
    /// post-apply UTXO/BurntKeys state is rejected, while the correct root is
    /// accepted. The header commits to the state, so a pruned/stateless node can
    /// verify a block without the full history.
    #[test]
    fn state_root_enforced() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let (blk, op) = coinbase(commit, Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        // Mature the genesis coinbase, then build a legitimate spend.
        let tip = extend(&mut store, blk.block_hash(), COINBASE_MATURITY);
        let kp2 = mldsa::MlDsaKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_hash160();
        let tx = spend(&kp, op, &commit, Amount(4 * 100_000_000), to);
        let b = block(tip, COINBASE_MATURITY + 1, vec![tx]);

        // Compute the state root that results from applying `b` (via a read-only
        // overlay, so the store is untouched).
        let root = block_state_root(&mut store, &b).unwrap();

        let mut good = b.clone();
        good.header.state_root = Hash32(root);
        assert!(connect_block(&good, &mut store, &EASY).is_ok());

        let mut bad = b.clone();
        bad.header.state_root = Hash32([0xABu8; 32]); // wrong, non-zero
        assert!(connect_block(&bad, &mut store, &EASY).is_err());
    }

    /// CRITICAL FIX #6 (checkpoints): a block at a checkpoint height must carry
    /// the pinned hash. This finalizes history at/below the checkpoint and
    /// bounds fast-sync snapshot trust (see `docs/state.md`). With no matching
    /// checkpoint the block is unaffected.
    #[test]
    fn checkpoint_enforced() {
        let blk = block(Hash32([0u8; 32]), 0, vec![]);
        let h = blk.block_hash();

        // No checkpoint at height 0 -> accepted.
        let none = ChainParams::testnet();
        assert!(validate_checkpoint(&blk, &none).is_ok());

        // A checkpoint at height 0 with the *correct* hash -> accepted.
        let mut good = ChainParams::testnet();
        good.checkpoints = vec![(0, h.0)];
        assert!(validate_checkpoint(&blk, &good).is_ok());

        // A checkpoint at height 0 with a *wrong* hash -> rejected.
        let mut wrong = ChainParams::testnet();
        wrong.checkpoints = vec![(0, [0x99u8; 32])];
        assert!(validate_checkpoint(&blk, &wrong).is_err());
    }

    /// CRITICAL FIX #5 (SignatureScheme): an input must declare an *active*
    /// signature scheme. Reserved ids (future post-quantum / hybrid schemes)
    /// are recognized but not yet active, and any unknown id is rejected —
    /// even when the WOTS+ signature itself is perfectly valid.
    #[test]
    fn reserved_signature_scheme_rejected() {
        let mut store = MemoryStore::new();
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let op = OutPoint {
            txid: Hash32([1u8; 32]),
            index: 0,
        };
        store.add_utxo(
            op.clone(),
            TxOut {
                value: Amount(5 * 100_000_000),
                script_pubkey: commit.to_vec(),
            },
        );
        let make_tx = |scheme: SignatureScheme| -> Transaction {
            let mut tx = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prevout: op.clone(),
                    scheme,
                    script_sig: vec![],
                    sequence: 0xFFFF_FFFF,
                }],
                outputs: vec![TxOut {
                    value: Amount(1),
                    script_pubkey: vec![0u8; 20],
                }],
                lock_time: 0,
            };
            let msg = sighash(&tx, 0, &commit);
            let pk = kp.public_key_bytes();
            let sig = kp.sign(&msg);
            let mut script_sig = Vec::with_capacity(mldsa::PK_LEN + mldsa::SIG_LEN);
            script_sig.extend_from_slice(&pk);
            script_sig.extend_from_slice(&sig);
            tx.inputs[0].script_sig = script_sig;
            tx
        };
        assert!(validate_tx(&make_tx(SignatureScheme::Reserved1), &store, 1).is_err());
        assert!(validate_tx(&make_tx(SignatureScheme::Unknown), &store, 1).is_err());
        assert!(validate_tx(&make_tx(SignatureScheme::Mldsa2), &store, 1).is_ok());
    }

    /// Helper: a signed spend of `prev` paying `value` to `to`, with a valid
    /// ML-DSA-2 signature but an arbitrary output value (so inflation tests can
    /// over-pay).
    fn signed_spend(
        kp: &mldsa::MlDsaKeypair,
        prev: OutPoint,
        prev_commit: &[u8; 20],
        value: Amount,
        to: [u8; 20],
    ) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: prev,
                scheme: SignatureScheme::Mldsa2,
                script_sig: vec![],
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: to.to_vec(),
            }],
            lock_time: 0,
        };
        let msg = sighash(&tx, 0, prev_commit);
        let pk = kp.public_key_bytes();
        let sig = kp.sign(&msg);
        let mut script_sig = Vec::with_capacity(mldsa::PK_LEN + mldsa::SIG_LEN);
        script_sig.extend_from_slice(&pk);
        script_sig.extend_from_slice(&sig);
        tx.inputs[0].script_sig = script_sig;
        tx
    }

    /// CRITICAL FIX #1: a spend whose outputs exceed its inputs must be rejected
    /// (no value creation / infinite inflation).
    #[test]
    fn inflation_via_outputs_rejected() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let (blk, op) = coinbase(commit, Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        let kp2 = mldsa::MlDsaKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_hash160();
        // Pay out 51 LIT while only owning 5 LIT.
        let tx = signed_spend(&kp, op.clone(), &commit, Amount(51 * 100_000_000), to);
        let b = block(blk.block_hash(), 1, vec![tx]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());
    }

    /// CRITICAL FIX #1: a coinbase may mint at most block_subsidy(height) (+ fees). Minting
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
        let (g, _) = coinbase([0u8; 20], Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&g, &mut store, &EASY).unwrap();
        let cb1 = cb([1u8; 20], Amount(5 * 100_000_000));
        let cb2 = cb([2u8; 20], Amount(5 * 100_000_000));
        let b = block(g.block_hash(), 1, vec![cb1, cb2]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());
    }

    /// CRITICAL FIX #2: an invalid transaction in a block must not partially
    /// mutate the UTXO set. After a rejected block the store is unchanged and
    /// the tip stays where it was.
    #[test]
    fn partial_apply_rolls_back() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let (blk, op) = coinbase(commit, Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();
        let before = litc_store::UtxoStore::iter_utxos(&store).len();

        let kp2 = mldsa::MlDsaKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_hash160();
        // Tx 0: valid spend of `op` (would consume it on apply).
        let good = signed_spend(&kp, op.clone(), &commit, Amount(4 * 100_000_000), to);
        // Tx 1: a coinbase that is not first -> rejected at block validation.
        let bad = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value: Amount(999),
                script_pubkey: to.to_vec(),
            }],
            lock_time: 0,
        };
        let b = block(blk.block_hash(), 1, vec![good, bad]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());

        // Nothing changed: `op` still unspent, count and tip unchanged.
        assert_eq!(litc_store::UtxoStore::iter_utxos(&store).len(), before);
        assert!(store.utxo(&op).is_some());
        assert_eq!(store.tip(), Some(blk.block_hash()));
    }

    /// CRITICAL FIX #1: spending the same UTXO twice inside one block is a
    /// double spend and must be rejected.
    #[test]
    fn intra_block_double_spend_rejected() {
        let kp = mldsa::MlDsaKeypair::derive(&[0x12u8; 32], 0);
        let commit = kp.pubkey_hash160();
        let (blk, op) = coinbase(commit, Amount(5 * 100_000_000), 0);
        let mut store = MemoryStore::new();
        connect_block(&blk, &mut store, &EASY).unwrap();

        let kp2 = mldsa::MlDsaKeypair::derive(&[0x34u8; 32], 0);
        let to = kp2.pubkey_hash160();
        let a = signed_spend(&kp, op.clone(), &commit, Amount(4 * 100_000_000), to);
        let b_tx = signed_spend(&kp, op.clone(), &commit, Amount(4 * 100_000_000), to);
        let b = block(blk.block_hash(), 1, vec![a, b_tx]);
        assert!(connect_block(&b, &mut store, &EASY).is_err());
    }
}
