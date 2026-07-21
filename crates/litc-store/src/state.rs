//! Consensus state abstraction and in-memory implementations.
//!
//! `StateRoot` is a pure function of the live consensus state: the UTXO set.
//! By design it MUST NOT depend on:
//! insertion order, `HashMap` iteration order, timestamps, caches, peers,
//! mempool, or the filesystem layout. See `docs/state.md`.
//!
//! The rest of the validator talks only to `StateStore`, never to a concrete
//! backend. Future backends (`SnapshotState`, `RocksDBState`, a persistent
//! Sparse Merkle Tree) plug in without touching validation logic.

use litc_primitives::{sha256d, OutPoint, TxOut};
use std::collections::{HashMap, HashSet};

/// A live UTXO entry: the output plus, if it is a coinbase output, the height
/// at which it was created (used for coinbase-maturity enforcement).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UtxoEntry {
    pub output: TxOut,
    pub coinbase_height: Option<u64>,
}

/// The portion of chain state that validation depends on: the unspent output
/// set. Abstracted so the rest of the code does not care whether state lives
/// in memory, an overlay, a snapshot, or a database.
pub trait StateStore {
    fn get_utxo(&self, op: &OutPoint) -> Option<UtxoEntry>;
    fn put_utxo(&mut self, op: OutPoint, entry: UtxoEntry);
    fn remove_utxo(&mut self, op: &OutPoint);
    /// Determinstic root committing to the full live state. See module docs.
    fn root(&self) -> [u8; 32];
    /// All unspent outputs.
    fn iter_utxos(&self) -> Vec<(OutPoint, UtxoEntry)>;
}

// ---------------------------------------------------------------------------
// Sparse Merkle Tree — deterministic, incremental-ready state root
// ---------------------------------------------------------------------------

/// 32-byte SMT key for a UTXO: `H(txid || index)`.
pub fn utxo_key(op: &OutPoint) -> [u8; 32] {
    let mut buf = Vec::with_capacity(36);
    buf.extend_from_slice(&op.txid.0);
    buf.extend_from_slice(&op.index.to_le_bytes());
    sha256d(&buf).0
}

/// Canonical leaf value for a UTXO entry (value, script, coinbase).
fn utxo_leaf_value(entry: &UtxoEntry) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&entry.output.value.0.to_le_bytes());
    b.extend_from_slice(&(entry.output.script_pubkey.len() as u32).to_le_bytes());
    b.extend_from_slice(&entry.output.script_pubkey);
    b.push(if entry.coinbase_height.is_some() { 1 } else { 0 });
    if let Some(h) = entry.coinbase_height {
        b.extend_from_slice(&h.to_le_bytes());
    }
    b
}

/// Memoized default hash of an empty subtree at a given depth (256 = leaf).
fn empty_hash(depth: usize) -> [u8; 32] {
    use std::sync::OnceLock;
    static EMPTY: OnceLock<Vec<[u8; 32]>> = OnceLock::new();
    let v = EMPTY.get_or_init(|| {
        let mut v = vec![[0u8; 32]; 257];
        for d in (0..256).rev() {
            v[d] = sha256d(&[v[d + 1], v[d + 1]].concat()).0;
        }
        v
    });
    v[depth]
}

fn leaf_hash(key: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut b = Vec::with_capacity(1 + 32 + value.len());
    b.push(0);
    b.extend_from_slice(key);
    b.extend_from_slice(value);
    sha256d(&b).0
}

/// Root of a Sparse Merkle Tree over `leaves` (key, value). Keys must be unique.
/// Deterministic and order-independent: leaves are sorted first. Internal nodes
/// are `H(left || right)`; empty subtrees use `empty_hash(depth)`. Membership
/// proofs fall out of this structure for free (added in a later stage).
pub fn smt_root(leaves: &mut [([u8; 32], Vec<u8>)]) -> [u8; 32] {
    leaves.sort_by_key(|a| a.0);
    build(leaves, 0)
}

fn build(leaves: &[([u8; 32], Vec<u8>)], depth: usize) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_hash(depth);
    }
    if depth == 256 {
        return leaf_hash(&leaves[0].0, &leaves[0].1);
    }
    // Descend by the MSB-first bit of the key at this depth.
    let bit = 255 - depth;
    let byte = bit / 8;
    let mask = 1u8 << (7 - (bit % 8));
    let split = leaves.partition_point(|(k, _)| (k[byte] & mask) == 0);
    let left = build(&leaves[..split], depth + 1);
    let right = build(&leaves[split..], depth + 1);
    sha256d(&[left, right].concat()).0
}

/// Canonical, order-independent `state_root` from the consensus state.
pub(crate) fn state_root_of(utxos: Vec<(OutPoint, UtxoEntry)>) -> [u8; 32] {
    let mut u: Vec<([u8; 32], Vec<u8>)> =
        utxos.iter().map(|(op, e)| (utxo_key(op), utxo_leaf_value(e))).collect();
    smt_root(&mut u)
}

/// In-memory `StateStore`. Suitable for tests, ephemeral nodes, and as the
/// backend behind an `OverlayState`.
#[derive(Clone, Default)]
pub struct MemoryState {
    utxos: HashMap<OutPoint, UtxoEntry>,
}

impl MemoryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_parts(utxos: HashMap<OutPoint, UtxoEntry>) -> Self {
        Self { utxos }
    }
}

impl StateStore for MemoryState {
    fn get_utxo(&self, op: &OutPoint) -> Option<UtxoEntry> {
        self.utxos.get(op).cloned()
    }
    fn put_utxo(&mut self, op: OutPoint, entry: UtxoEntry) {
        self.utxos.insert(op, entry);
    }
    fn remove_utxo(&mut self, op: &OutPoint) {
        self.utxos.remove(op);
    }
    fn root(&self) -> [u8; 32] {
        let utxos: Vec<(OutPoint, UtxoEntry)> = self
            .utxos
            .iter()
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect();
        state_root_of(utxos)
    }
    fn iter_utxos(&self) -> Vec<(OutPoint, UtxoEntry)> {
        self.utxos
            .iter()
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect()
    }
}

/// Copy-on-write overlay over a base `StateStore` (held by mutable reference).
/// Modifications are recorded in small maps, never copying the whole base (a
/// node with 10M UTXOs must not duplicate them per block). Reads fall through
/// to the base; `root` computes over the merged view; `commit` flushes the
/// overlay into the base. This is the unit of atomic block application: apply
/// to an overlay, compute the `state_root`, compare with `header.state_root`,
/// then `commit` (or drop to leave the base untouched).
pub struct OverlayState<'a, S: StateStore> {
    base: &'a mut S,
    puts: HashMap<OutPoint, UtxoEntry>,
    removes: HashSet<OutPoint>,
}

impl<'a, S: StateStore> OverlayState<'a, S> {
    pub fn new(base: &'a mut S) -> Self {
        Self {
            base,
            puts: HashMap::new(),
            removes: HashSet::new(),
        }
    }

    /// Flush all recorded modifications into the base state.
    pub fn commit(self) {
        let base = self.base;
        for op in &self.removes {
            base.remove_utxo(op);
        }
        for (op, e) in self.puts {
            base.put_utxo(op, e);
        }
    }

    fn merged(&self) -> Vec<(OutPoint, UtxoEntry)> {
        let mut utxos: Vec<(OutPoint, UtxoEntry)> = Vec::new();
        for (op, e) in self.base.iter_utxos() {
            if !self.removes.contains(&op) {
                utxos.push((op, e));
            }
        }
        for (op, e) in &self.puts {
            utxos.push((op.clone(), e.clone()));
        }
        utxos
    }
}

impl<'a, S: StateStore> StateStore for OverlayState<'a, S> {
    fn get_utxo(&self, op: &OutPoint) -> Option<UtxoEntry> {
        if self.removes.contains(op) {
            return None;
        }
        if let Some(e) = self.puts.get(op) {
            return Some(e.clone());
        }
        self.base.get_utxo(op)
    }
    fn put_utxo(&mut self, op: OutPoint, entry: UtxoEntry) {
        self.removes.remove(&op);
        self.puts.insert(op, entry);
    }
    fn remove_utxo(&mut self, op: &OutPoint) {
        self.puts.remove(op);
        self.removes.insert(op.clone());
    }
    fn root(&self) -> [u8; 32] {
        let utxos = self.merged();
        state_root_of(utxos)
    }
    fn iter_utxos(&self) -> Vec<(OutPoint, UtxoEntry)> {
        self.merged()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litc_primitives::{Amount, Hash32};

    fn op(i: u8, index: u32) -> OutPoint {
        let mut t = [0u8; 32];
        t[0] = i;
        OutPoint {
            txid: Hash32(t),
            index,
        }
    }

    fn entry(value: u64, cb: Option<u64>) -> UtxoEntry {
        UtxoEntry {
            output: TxOut {
                value: Amount(value),
                script_pubkey: vec![0u8; 20],
            },
            coinbase_height: cb,
        }
    }

    #[test]
    fn state_root_is_order_independent() {
        let mut a = MemoryState::new();
        a.put_utxo(op(1, 0), entry(10, None));
        a.put_utxo(op(2, 0), entry(20, Some(0)));
        a.put_utxo(op(3, 1), entry(30, None));

        let mut b = MemoryState::new();
        b.put_utxo(op(3, 1), entry(30, None));
        b.put_utxo(op(1, 0), entry(10, None));
        b.put_utxo(op(2, 0), entry(20, Some(0)));

        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn overlay_matches_direct_application() {
        let mut direct = MemoryState::new();
        direct.put_utxo(op(1, 0), entry(100, Some(0)));
        direct.put_utxo(op(2, 0), entry(50, None));
        direct.remove_utxo(&op(1, 0));
        direct.put_utxo(op(3, 0), entry(70, None));

        let mut base = MemoryState::new();
        base.put_utxo(op(1, 0), entry(100, Some(0)));
        let mut ov = OverlayState::new(&mut base);
        ov.remove_utxo(&op(1, 0));
        ov.put_utxo(op(2, 0), entry(50, None));
        ov.put_utxo(op(3, 0), entry(70, None));

        assert_eq!(ov.root(), direct.root());

        ov.commit();
        assert_eq!(base.root(), direct.root());
        assert_eq!(base.get_utxo(&op(1, 0)), None);
        assert_eq!(base.get_utxo(&op(2, 0)), Some(entry(50, None)));
        assert_eq!(base.get_utxo(&op(3, 0)), Some(entry(70, None)));
    }

    #[test]
    fn overlay_merges_base_and_changes() {
        let mut base = MemoryState::new();
        base.put_utxo(op(1, 0), entry(100, Some(0)));

        let mut ov = OverlayState::new(&mut base);
        ov.put_utxo(op(2, 0), entry(5, None));
        ov.remove_utxo(&op(1, 0));

        assert_eq!(ov.get_utxo(&op(1, 0)), None);
        assert_eq!(ov.get_utxo(&op(2, 0)), Some(entry(5, None)));
    }
}
