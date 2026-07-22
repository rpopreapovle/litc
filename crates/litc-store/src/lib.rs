//! Storage traits and implementations for LiTC.
//!
//! Storage is split into traits so each part (blocks, chain index, UTXO set)
//! can change independently. Two implementations are provided:
//! [`MemoryStore`] (in-memory, for tests and ephemeral nodes) and
//! [`FileStore`] (append-only block store with continuous pruning for real
//! nodes — see `docs/running-a-node.md`).
#![allow(clippy::items_after_test_module)]

use litc_primitives::{
    Amount, Block, BlockHeader, Decodable, Encodable, Hash32, OutPoint, Reader, Transaction, TxOut,
};
use litc_primitives::chainparams::ChainParams;
use std::collections::{HashMap, HashSet};

pub mod state;

/// A UTXO set, as persisted in `utxo.dat`.
type UtxoSets = HashMap<OutPoint, TxOut>;

/// Records the UTXO changes a block made, so they can be
/// rolled back on a chain reorganisation. `created` are outputs the block
/// added, `spent` are outputs it consumed (with their values, to restore).
#[derive(Clone, Default)]
pub struct UndoData {
    pub created: Vec<OutPoint>,
    pub spent: Vec<(OutPoint, TxOut)>,
    /// Coinbase outputs this block created, with the height at which they were
    /// created (so `disconnect` can drop them).
    pub coinbase_created: Vec<(OutPoint, u64)>,
    /// Coinbase outputs this block spent, with their creation height (so
    /// `disconnect` can restore the maturity index).
    pub coinbase_spent: Vec<(OutPoint, u64)>,
}
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Append/get blocks and track the best tip.
pub trait BlockStore {
    fn put_block(&mut self, block: &Block) -> Result<(), String>;
    fn get_block(&self, hash: &Hash32) -> Option<Block>;
    fn has_block(&self, hash: &Hash32) -> bool;
}

/// Chain/height indexing and the current best tip.
pub trait ChainStore {
    fn set_tip(&mut self, hash: Hash32, height: u64);
    fn tip(&self) -> Option<Hash32>;
    fn height_of(&self, hash: &Hash32) -> Option<u64>;
}

/// The unspent output set.
pub trait UtxoStore {
    fn add_utxo(&mut self, outpoint: OutPoint, output: TxOut);
    fn spend_utxo(&mut self, outpoint: &OutPoint) -> Result<TxOut, String>;
    fn utxo(&self, outpoint: &OutPoint) -> Option<&TxOut>;
    /// Find the outpoint whose `script_pubkey` is the given 20-byte commitment.
    fn find_by_commit(&self, commit: &[u8; 20]) -> Option<OutPoint>;
    /// Iterate every unspent output.
    fn iter_utxos(&self) -> Vec<(OutPoint, TxOut)>;
    /// Remove an unspent output without recording a spend (e.g. when moving a
    /// UTXO forward during a test/migration). Used by the fast-sync e2e test.
    fn remove_utxo(&mut self, outpoint: &OutPoint);
}

/// Store abilities the validator needs: a UTXO set.
/// Defined here (not in `litc-core`) to avoid a dependency cycle:
/// `litc-core` depends on `litc-store`.
///
/// The extra methods drive chain selection by cumulative work and
/// reorganisations: the node records per-block `UndoData` (via
/// `begin_block`/`end_block`), can roll a block back with `disconnect`,
/// and tracks cumulative `work` so the heaviest chain wins.
pub trait SpendStore: UtxoStore + BlockStore + ChainStore {
    /// Record that `op` is a coinbase output created at `height`. Used to
    /// enforce coinbase maturity: a coinbase UTXO may not be spent until
    /// `COINBASE_MATURITY` blocks have been mined on top of its block.
    fn mark_coinbase(&mut self, op: &OutPoint, height: u64);
    /// Creation height of `op` if it is a coinbase output, else `None`.
    fn coinbase_height(&self, op: &OutPoint) -> Option<u64>;

    /// Begin recording a block's UTXO changes for later rollback.
    fn begin_block(&mut self, hash: Hash32);
    /// Finish recording; store the captured `UndoData` under `hash`.
    fn end_block(&mut self);
    /// Undo data recorded for `hash`, if any.
    fn get_undo(&self, hash: &Hash32) -> Option<UndoData>;
    /// Roll a previously-applied block back (restore spent UTXOs).
    fn disconnect(&mut self, hash: &Hash32);

    /// Remember that `hash` already passed Proof-of-Work validation.
    fn remember_pow(&mut self, hash: Hash32);
    fn is_pow_valid(&self, hash: &Hash32) -> bool;

    /// Record (cumulative) work for a block so the heaviest chain can be chosen.
    fn set_work(&mut self, hash: Hash32, work: u128);
    fn work_of(&self, hash: &Hash32) -> u128;

    /// Mark a block as applied to the live UTXO set (part of the active chain).
    fn mark_applied(&mut self, hash: Hash32);
    fn is_applied(&self, hash: &Hash32) -> bool;

    /// Best known block by cumulative work (highest work, then height).
    fn best_tip_by_work(&self) -> Option<Hash32>;
    /// Parent block hash of `hash` (zero hash for genesis).
    fn parent_of(&self, hash: &Hash32) -> Option<Hash32>;
}

impl SpendStore for MemoryStore {
    fn mark_coinbase(&mut self, op: &OutPoint, height: u64) {
        self.coinbase.insert(op.clone(), height);
        if let Some((_, u)) = &mut self.current {
            u.coinbase_created.push((op.clone(), height));
        }
    }
    fn coinbase_height(&self, op: &OutPoint) -> Option<u64> {
        self.coinbase.get(op).copied()
    }

    fn begin_block(&mut self, hash: Hash32) {
        self.begin_block(hash);
    }
    fn end_block(&mut self) {
        self.end_block();
    }
    fn get_undo(&self, hash: &Hash32) -> Option<UndoData> {
        self.get_undo(hash)
    }
    fn disconnect(&mut self, hash: &Hash32) {
        self.disconnect(hash);
    }
    fn remember_pow(&mut self, hash: Hash32) {
        self.remember_pow(hash);
    }
    fn is_pow_valid(&self, hash: &Hash32) -> bool {
        self.is_pow_valid(hash)
    }
    fn set_work(&mut self, hash: Hash32, work: u128) {
        self.set_work(hash, work);
    }
    fn work_of(&self, hash: &Hash32) -> u128 {
        self.work_of(hash)
    }
    fn mark_applied(&mut self, hash: Hash32) {
        self.mark_applied(hash);
    }
    fn is_applied(&self, hash: &Hash32) -> bool {
        self.is_applied(hash)
    }
    fn best_tip_by_work(&self) -> Option<Hash32> {
        self.best_tip_by_work()
    }
    fn parent_of(&self, hash: &Hash32) -> Option<Hash32> {
        self.parent_of(hash)
    }
}

// ---------------------------------------------------------------------------
// MemoryStore
// ---------------------------------------------------------------------------

/// In-memory implementation of all store traits.
#[derive(Default)]
pub struct MemoryStore {
    blocks: HashMap<Hash32, Block>,
    height: HashMap<Hash32, u64>,
    tip: Option<Hash32>,
    utxos: HashMap<OutPoint, TxOut>,
    /// Creation height of every live coinbase output, so spends can be checked
    /// against the coinbase-maturity rule.
    coinbase: HashMap<OutPoint, u64>,
    // --- reorg / chain-selection state ---
    work: HashMap<Hash32, u128>,
    applied: HashSet<Hash32>,
    undo: HashMap<Hash32, UndoData>,
    pow_ok: HashSet<Hash32>,
    current: Option<(Hash32, UndoData)>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Best known chain height (derived from the current tip).
    pub fn best_height(&self) -> u64 {
        self.tip
            .and_then(|h| self.height.get(&h).copied())
            .unwrap_or(0)
    }

    // --- reorg / chain-selection helpers --------------------------------
    pub fn set_work(&mut self, hash: Hash32, work: u128) {
        self.work.insert(hash, work);
    }
    pub fn work_of(&self, hash: &Hash32) -> u128 {
        self.work.get(hash).copied().unwrap_or(0)
    }
    pub fn remember_pow(&mut self, hash: Hash32) {
        self.pow_ok.insert(hash);
    }
    pub fn is_pow_valid(&self, hash: &Hash32) -> bool {
        self.pow_ok.contains(hash)
    }
    pub fn mark_applied(&mut self, hash: Hash32) {
        self.applied.insert(hash);
    }
    pub fn is_applied(&self, hash: &Hash32) -> bool {
        self.applied.contains(hash)
    }
    pub fn parent_of(&self, hash: &Hash32) -> Option<Hash32> {
        self.blocks.get(hash).map(|b| b.header.prev_block)
    }
    pub fn get_undo(&self, hash: &Hash32) -> Option<UndoData> {
        self.undo.get(hash).cloned()
    }
    /// Best block by cumulative work: highest work, tie-break by height.
    pub fn best_tip_by_work(&self) -> Option<Hash32> {
        let mut best: Option<(u128, u64, Hash32)> = None;
        for (h, w) in &self.work {
            let height = self.height.get(h).copied().unwrap_or(0);
            let cand = (*w, height, *h);
            match best {
                None => best = Some(cand),
                Some(b) => {
                    let better = cand.0 > b.0
                        || (cand.0 == b.0 && cand.1 > b.1)
                        || (cand.0 == b.0 && cand.1 == b.1 && cand.2 .0 < b.2 .0);
                    if better {
                        best = Some(cand);
                    }
                }
            }
        }
        best.map(|b| b.2)
    }
    pub fn begin_block(&mut self, hash: Hash32) {
        self.current = Some((hash, UndoData::default()));
    }
    pub fn end_block(&mut self) {
        if let Some((h, u)) = self.current.take() {
            self.undo.insert(h, u);
        }
    }
    /// Roll back a previously-applied block: drop created outputs, restore
    /// spent outputs.
    pub fn disconnect(&mut self, hash: &Hash32) {
        if let Some(u) = self.undo.remove(hash) {
            for op in &u.created {
                self.utxos.remove(op);
            }
            for (op, out) in &u.spent {
                self.utxos.insert(op.clone(), out.clone());
            }
            for (op, _) in &u.coinbase_created {
                self.coinbase.remove(op);
            }
            for (op, h) in &u.coinbase_spent {
                self.coinbase.insert(op.clone(), *h);
            }
        }
        self.applied.remove(hash);
    }
}

impl BlockStore for MemoryStore {
    fn put_block(&mut self, block: &Block) -> Result<(), String> {
        self.blocks.insert(block.block_hash(), block.clone());
        self.height.insert(block.block_hash(), block.header.height);
        Ok(())
    }
    fn get_block(&self, hash: &Hash32) -> Option<Block> {
        self.blocks.get(hash).cloned()
    }
    fn has_block(&self, hash: &Hash32) -> bool {
        self.blocks.contains_key(hash)
    }
}

impl ChainStore for MemoryStore {
    fn set_tip(&mut self, hash: Hash32, height: u64) {
        self.height.insert(hash, height);
        self.tip = Some(hash);
    }
    fn tip(&self) -> Option<Hash32> {
        self.tip
    }
    fn height_of(&self, hash: &Hash32) -> Option<u64> {
        self.height.get(hash).copied()
    }
}

impl UtxoStore for MemoryStore {
    fn add_utxo(&mut self, outpoint: OutPoint, output: TxOut) {
        if let Some((_, u)) = &mut self.current {
            u.created.push(outpoint.clone());
        }
        self.utxos.insert(outpoint, output);
    }
    fn spend_utxo(&mut self, outpoint: &OutPoint) -> Result<TxOut, String> {
        let out = self
            .utxos
            .remove(outpoint)
            .ok_or_else(|| "utxo not found".to_string())?;
        if let Some((_, u)) = &mut self.current {
            u.spent.push((outpoint.clone(), out.clone()));
        }
        if let Some(h) = self.coinbase.remove(outpoint) {
            if let Some((_, u)) = &mut self.current {
                u.coinbase_spent.push((outpoint.clone(), h));
            }
        }
        Ok(out)
    }
    fn utxo(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.utxos.get(outpoint)
    }
    fn find_by_commit(&self, commit: &[u8; 20]) -> Option<OutPoint> {
        for (op, out) in &self.utxos {
            if out.script_pubkey.len() >= 20 && &out.script_pubkey[..20] == commit {
                return Some(op.clone());
            }
        }
        None
    }
    fn iter_utxos(&self) -> Vec<(OutPoint, TxOut)> {
        self.utxos
            .iter()
            .map(|(op, out)| (op.clone(), out.clone()))
            .collect()
    }
    fn remove_utxo(&mut self, outpoint: &OutPoint) {
        self.utxos.remove(outpoint);
    }
}

impl state::StateStore for MemoryStore {
    fn get_utxo(&self, op: &OutPoint) -> Option<state::UtxoEntry> {
        self.utxos.get(op).map(|out| state::UtxoEntry {
            output: TxOut {
                value: out.value,
                script_pubkey: out.script_pubkey.clone(),
            },
            coinbase_height: self.coinbase.get(op).copied(),
        })
    }
    fn put_utxo(&mut self, op: OutPoint, entry: state::UtxoEntry) {
        self.add_utxo(op.clone(), entry.output.clone());
        if let Some(h) = entry.coinbase_height {
            self.mark_coinbase(&op, h);
        }
    }
    fn remove_utxo(&mut self, op: &OutPoint) {
        let _ = self.spend_utxo(op);
    }
    fn root(&self) -> [u8; 32] {
        let utxos: Vec<(OutPoint, state::UtxoEntry)> = self
            .utxos
            .iter()
            .map(|(op, out)| {
                (
                    op.clone(),
                    state::UtxoEntry {
                        output: TxOut {
                            value: out.value,
                            script_pubkey: out.script_pubkey.clone(),
                        },
                        coinbase_height: self.coinbase.get(op).copied(),
                    },
                )
            })
            .collect();
        state::state_root_of(utxos)
    }
    fn iter_utxos(&self) -> Vec<(OutPoint, state::UtxoEntry)> {
        self.utxos
            .iter()
            .map(|(op, out)| {
                (
                    op.clone(),
                    state::UtxoEntry {
                        output: TxOut {
                            value: out.value,
                            script_pubkey: out.script_pubkey.clone(),
                        },
                        coinbase_height: self.coinbase.get(op).copied(),
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litc_primitives::{
        Amount, Block, BlockHeader, Hash32, OutPoint, Transaction, TxOut,
    };

    fn coinbase(commit: [u8; 20]) -> (Block, OutPoint) {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOut {
                value: Amount(5 * 100_000_000),
                script_pubkey: commit.to_vec(),
            }],
            lock_time: 0,
        };
        let op = litc_primitives::OutPoint {
            txid: tx.txid(),
            index: 0,
        };
        let block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: Hash32([0u8; 32]),
                merkle_root: Hash32([0u8; 32]),
                state_root: Hash32([0u8; 32]),
                timestamp: 0,
                height: 0,
                epoch_seed: Hash32([0u8; 32]),
                nonce: 0,
            },
            txs: vec![tx],
        };
        (block, op)
    }

    #[test]
    fn block_roundtrip() {
        let (block, _) = coinbase([1u8; 20]);
        let mut s = MemoryStore::new();
        s.put_block(&block).unwrap();
        assert!(s.has_block(&block.block_hash()));
        assert_eq!(s.get_block(&block.block_hash()), Some(block));
    }

    #[test]
    fn utxo_spend() {
        let (block, op) = coinbase([2u8; 20]);
        let mut s = MemoryStore::new();
        for tx in &block.txs {
            for (i, out) in tx.outputs.iter().enumerate() {
                s.add_utxo(
                    litc_primitives::OutPoint {
                        txid: tx.txid(),
                        index: i as u32,
                    },
                    out.clone(),
                );
            }
        }
        assert!(s.utxo(&op).is_some());
        let spent = s.spend_utxo(&op).unwrap();
        assert_eq!(spent.value, Amount(5 * 100_000_000));
        assert!(s.utxo(&op).is_none());
        assert!(s.spend_utxo(&op).is_err());
    }
}

// ---------------------------------------------------------------------------
// FileStore — persistent, prunable chain state for the node and CLI wallet
//
// Disk layout under the data directory:
//   chain.dat   append-only block records (header always; body optionally)
//   chain.idx   tiny sidecar: per-height (offset, len, has_body) entries
//   utxo.dat    flat list of *live* outputs (rewritten on each UTXO change)
//   tip.dat     32-byte current tip hash
//
// Pruning keeps only the last `keep_depth` block bodies on disk; older blocks
// are rewritten as header-only, so disk usage stays bounded while every header
// (a few dozen bytes) is retained for chain verification. All block reads go
// through `chain.idx` offsets via `seek` — the file is never slurped whole.
// ---------------------------------------------------------------------------

/// Pruning configuration. When `Some`, `FileStore` drops block bodies older
/// than `keep_depth` blocks from the tip.
pub struct PruneConfig {
    pub keep_depth: u64,
}

// --- snapshot.meta: the only trust anchor for a fast-syncing node ------------
const SNAPSHOT_MAGIC: &[u8; 4] = b"LITS";
const SNAPSHOT_VERSION: u32 = 1;

/// Self-describing snapshot header. The only trust anchor is `state_root`: a
/// loader recomputes it from the loaded UTXO set and rejects the snapshot
/// if it does not match. `work` lets the fast-synced node keep the snapshot tip
/// as its best chain for reorg comparisons against new blocks.
pub struct SnapshotMeta {
    pub magic: [u8; 4],
    pub version: u32,
    pub height: u64,
    pub block_hash: Hash32,
    pub work: u128,
    pub state_root: [u8; 32],
}

impl SnapshotMeta {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 4 + 8 + 32 + 16 + 32);
        v.extend_from_slice(&self.magic);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.block_hash.0);
        v.extend_from_slice(&self.work.to_le_bytes());
        v.extend_from_slice(&self.state_root);
        v
    }
    fn decode(b: &[u8]) -> Result<Self, String> {
        if b.len() < 4 + 4 + 8 + 32 + 16 + 32 {
            return Err("corrupt snapshot.meta".into());
        }
        let mut p = 0;
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&b[p..p + 4]);
        p += 4;
        let version = u32::from_le_bytes(b[p..p + 4].try_into().unwrap());
        p += 4;
        let height = u64::from_le_bytes(b[p..p + 8].try_into().unwrap());
        p += 8;
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&b[p..p + 32]);
        p += 32;
        let work = u128::from_le_bytes(b[p..p + 16].try_into().unwrap());
        p += 16;
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&b[p..p + 32]);
        if &magic != SNAPSHOT_MAGIC {
            return Err("bad snapshot magic".into());
        }
        Ok(SnapshotMeta {
            magic,
            version,
            height,
            block_hash: Hash32(block_hash),
            work,
            state_root,
        })
    }
}

// --- chain.dat record (length-prefixed, self-describing) -------------------
// height: u64 | has_body: u8 | header_len: u32 | header | (body_len: u32 | body)?

fn write_block_record(
    f: &mut File,
    height: u64,
    has_body: bool,
    header: &BlockHeader,
    txs: &[Transaction],
) -> std::io::Result<(u64, u64)> {
    let start = f.stream_position()?;
    f.write_all(&height.to_le_bytes())?;
    f.write_all(&[has_body as u8])?;
    let mut hb = Vec::new();
    header.encode(&mut hb);
    f.write_all(&(hb.len() as u32).to_le_bytes())?;
    f.write_all(&hb)?;
    if has_body {
        let mut bb = Vec::new();
        txs.to_vec().encode(&mut bb);
        f.write_all(&(bb.len() as u32).to_le_bytes())?;
        f.write_all(&bb)?;
    }
    let end = f.stream_position()?;
    Ok((start, end))
}

#[allow(clippy::type_complexity)]
fn read_block_record(
    f: &mut File,
    offset: u64,
) -> std::io::Result<(u64, bool, BlockHeader, Vec<Transaction>)> {
    f.seek(SeekFrom::Start(offset))?;
    let mut b8 = [0u8; 8];
    f.read_exact(&mut b8)?;
    let height = u64::from_le_bytes(b8);
    let mut flag = [0u8; 1];
    f.read_exact(&mut flag)?;
    let has_body = flag[0] != 0;
    let mut l4 = [0u8; 4];
    f.read_exact(&mut l4)?;
    let hlen = u32::from_le_bytes(l4) as usize;
    let mut hb = vec![0u8; hlen];
    f.read_exact(&mut hb)?;
    let header = BlockHeader::decode(&mut Reader::new(&hb))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let txs = if has_body {
        let mut l4b = [0u8; 4];
        f.read_exact(&mut l4b)?;
        let blen = u32::from_le_bytes(l4b) as usize;
        let mut bb = vec![0u8; blen];
        f.read_exact(&mut bb)?;
        Vec::<Transaction>::decode(&mut Reader::new(&bb))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
    } else {
        Vec::new()
    };
    Ok((height, has_body, header, txs))
}

// --- chain.idx -------------------------------------------------------------
// [ count: u64 ][ for each: height:u64 | offset:u64 | len:u64 | has_body:u8 ]

#[allow(clippy::type_complexity)]
fn write_index(path: &Path, idx: &HashMap<u64, (u64, u64, bool)>) -> std::io::Result<()> {
    let mut w = Vec::new();
    let mut heights: Vec<u64> = idx.keys().copied().collect();
    heights.sort_unstable();
    w.extend_from_slice(&(heights.len() as u64).to_le_bytes());
    for h in heights {
        let (off, len, hb) = idx[&h];
        w.extend_from_slice(&h.to_le_bytes());
        w.extend_from_slice(&off.to_le_bytes());
        w.extend_from_slice(&len.to_le_bytes());
        w.push(hb as u8);
    }
    fs::write(path, w)
}

#[allow(clippy::type_complexity)]
fn parse_index(buf: &[u8]) -> Result<HashMap<u64, (u64, u64, bool)>, String> {
    if buf.len() < 8 {
        return Err("corrupt chain index".into());
    }
    let mut pos = 0;
    let mut c = [0u8; 8];
    c.copy_from_slice(&buf[pos..pos + 8]);
    pos += 8;
    let count = u64::from_le_bytes(c);
    let mut idx = HashMap::new();
    for _ in 0..count {
        let mut h = [0u8; 8];
        h.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        let mut off = [0u8; 8];
        off.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        let mut len = [0u8; 8];
        len.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        let hb = buf[pos] != 0;
        pos += 1;
        idx.insert(
            u64::from_le_bytes(h),
            (u64::from_le_bytes(off), u64::from_le_bytes(len), hb),
        );
    }
    Ok(idx)
}

// --- utxo.dat: flat list of live outputs ------------------------------------
// count:u32 | for each: txid:32 | index:u32 | value:u64 | script_len:u32
//                    | script

fn write_utxos(
    path: &Path,
    utxos: &HashMap<OutPoint, TxOut>,
) -> std::io::Result<()> {
    let mut w = Vec::new();
    w.extend_from_slice(&(utxos.len() as u32).to_le_bytes());
    for (op, out) in utxos {
        w.extend_from_slice(&op.txid.0);
        w.extend_from_slice(&op.index.to_le_bytes());
        w.extend_from_slice(&(out.value.0).to_le_bytes());
        w.extend_from_slice(&(out.script_pubkey.len() as u32).to_le_bytes());
        w.extend_from_slice(&out.script_pubkey);
    }
    fs::write(path, w)
}

fn parse_utxos(buf: &[u8]) -> Result<UtxoSets, String> {
    if buf.len() < 4 {
        return Err("corrupt utxo file".into());
    }
    let mut pos = 0;
    let mut c = [0u8; 4];
    c.copy_from_slice(&buf[pos..pos + 4]);
    pos += 4;
    let count = u32::from_le_bytes(c);
    let mut map = HashMap::new();
    for _ in 0..count {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        let mut idx = [0u8; 4];
        idx.copy_from_slice(&buf[pos..pos + 4]);
        pos += 4;
        let mut val = [0u8; 8];
        val.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        let mut sl = [0u8; 4];
        sl.copy_from_slice(&buf[pos..pos + 4]);
        pos += 4;
        let slen = u32::from_le_bytes(sl) as usize;
        let script = buf[pos..pos + slen].to_vec();
        pos += slen;
        map.insert(
            OutPoint {
                txid: Hash32(txid),
                index: u32::from_le_bytes(idx),
            },
            TxOut {
                value: Amount(u64::from_le_bytes(val)),
                script_pubkey: script,
            },
        );
    }
    Ok(map)
}

// --- coinbase.dat: live coinbase outputs and the height they were created at
// count:u32 | for each: txid:32 | index:u32 | height:u64

fn write_coinbase(path: &Path, coinbase: &HashMap<OutPoint, u64>) -> std::io::Result<()> {
    let mut w = Vec::new();
    w.extend_from_slice(&(coinbase.len() as u32).to_le_bytes());
    for (op, h) in coinbase {
        w.extend_from_slice(&op.txid.0);
        w.extend_from_slice(&op.index.to_le_bytes());
        w.extend_from_slice(&h.to_le_bytes());
    }
    fs::write(path, w)
}

fn parse_coinbase(buf: &[u8]) -> Result<HashMap<OutPoint, u64>, String> {
    if buf.len() < 4 {
        return Err("corrupt coinbase file".into());
    }
    let mut pos = 0usize;
    let mut c = [0u8; 4];
    c.copy_from_slice(&buf[pos..pos + 4]);
    pos += 4;
    let count = u32::from_le_bytes(c) as usize;
    if buf.len() < 4 + count * 44 {
        return Err("corrupt coinbase file".into());
    }
    let mut map = HashMap::new();
    for _ in 0..count {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        let mut idx = [0u8; 4];
        idx.copy_from_slice(&buf[pos..pos + 4]);
        pos += 4;
        let mut h = [0u8; 8];
        h.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        map.insert(
            OutPoint {
                txid: Hash32(txid),
                index: u32::from_le_bytes(idx),
            },
            u64::from_le_bytes(h),
        );
    }
    Ok(map)
}

// --- chainmeta.dat: (work, applied, pow_ok) for restart-safe chain state ---
fn write_meta(
    path: &Path,
    work: &HashMap<Hash32, u128>,
    applied: &HashSet<Hash32>,
    pow_ok: &HashSet<Hash32>,
) -> std::io::Result<()> {
    let mut w = Vec::new();
    w.extend_from_slice(&(work.len() as u32).to_le_bytes());
    for (h, wk) in work {
        w.extend_from_slice(&h.0);
        w.extend_from_slice(&wk.to_le_bytes());
    }
    w.extend_from_slice(&(applied.len() as u32).to_le_bytes());
    for h in applied {
        w.extend_from_slice(&h.0);
    }
    w.extend_from_slice(&(pow_ok.len() as u32).to_le_bytes());
    for h in pow_ok {
        w.extend_from_slice(&h.0);
    }
    fs::write(path, w)
}

#[allow(clippy::type_complexity)]
fn parse_meta(buf: &[u8]) -> (HashMap<Hash32, u128>, HashSet<Hash32>, HashSet<Hash32>) {
    let mut pos = 0usize;
    let mut c4 = [0u8; 4];
    let mut tk = |n: usize| -> &[u8] {
        let s = &buf[pos..pos + n];
        pos += n;
        s
    };
    let mut work = HashMap::new();
    c4.copy_from_slice(tk(4));
    let nw = u32::from_le_bytes(c4) as usize;
    for _ in 0..nw {
        let mut h = [0u8; 32];
        h.copy_from_slice(tk(32));
        let mut w = [0u8; 16];
        w.copy_from_slice(tk(16));
        work.insert(Hash32(h), u128::from_le_bytes(w));
    }
    let mut applied = HashSet::new();
    c4.copy_from_slice(tk(4));
    let na = u32::from_le_bytes(c4) as usize;
    for _ in 0..na {
        let mut h = [0u8; 32];
        h.copy_from_slice(tk(32));
        applied.insert(Hash32(h));
    }
    let mut pow_ok = HashSet::new();
    c4.copy_from_slice(tk(4));
    let np = u32::from_le_bytes(c4) as usize;
    for _ in 0..np {
        let mut h = [0u8; 32];
        h.copy_from_slice(tk(32));
        pow_ok.insert(Hash32(h));
    }
    (work, applied, pow_ok)
}

// --- undo.dat: recorded UndoData per applied block (for reorgs) ------------
fn write_undo(path: &Path, undo: &HashMap<Hash32, UndoData>) -> std::io::Result<()> {
    let mut w = Vec::new();
    w.extend_from_slice(&(undo.len() as u32).to_le_bytes());
    for (h, u) in undo {
        w.extend_from_slice(&h.0);
        w.extend_from_slice(&(u.created.len() as u32).to_le_bytes());
        for op in &u.created {
            w.extend_from_slice(&op.txid.0);
            w.extend_from_slice(&op.index.to_le_bytes());
        }
        w.extend_from_slice(&(u.spent.len() as u32).to_le_bytes());
        for (op, out) in &u.spent {
            w.extend_from_slice(&op.txid.0);
            w.extend_from_slice(&op.index.to_le_bytes());
            w.extend_from_slice(&out.value.0.to_le_bytes());
            w.extend_from_slice(&(out.script_pubkey.len() as u32).to_le_bytes());
            w.extend_from_slice(&out.script_pubkey);
        }
        w.extend_from_slice(&(u.coinbase_created.len() as u32).to_le_bytes());
        for (op, h) in &u.coinbase_created {
            w.extend_from_slice(&op.txid.0);
            w.extend_from_slice(&op.index.to_le_bytes());
            w.extend_from_slice(&h.to_le_bytes());
        }
        w.extend_from_slice(&(u.coinbase_spent.len() as u32).to_le_bytes());
        for (op, h) in &u.coinbase_spent {
            w.extend_from_slice(&op.txid.0);
            w.extend_from_slice(&op.index.to_le_bytes());
            w.extend_from_slice(&h.to_le_bytes());
        }
    }
    fs::write(path, w)
}

fn parse_undo(buf: &[u8]) -> HashMap<Hash32, UndoData> {
    let mut pos = 0usize;
    macro_rules! take {
        ($n:expr) => {{
            let s = &buf[pos..pos + $n];
            pos += $n;
            s
        }};
    }
    let mut c4 = [0u8; 4];
    c4.copy_from_slice(take!(4));
    let n = u32::from_le_bytes(c4) as usize;
    let mut map = HashMap::new();
    for _ in 0..n {
        let mut h = [0u8; 32];
        h.copy_from_slice(take!(32));
        let mut cu = [0u8; 4];
        cu.copy_from_slice(take!(4));
        let nc = u32::from_le_bytes(cu) as usize;
        let mut created = Vec::new();
        for _ in 0..nc {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(take!(32));
            let mut ix = [0u8; 4];
            ix.copy_from_slice(take!(4));
            created.push(OutPoint {
                txid: Hash32(txid),
                index: u32::from_le_bytes(ix),
            });
        }
        cu.copy_from_slice(take!(4));
        let ns = u32::from_le_bytes(cu) as usize;
        let mut spent = Vec::new();
        for _ in 0..ns {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(take!(32));
            let mut ix = [0u8; 4];
            ix.copy_from_slice(take!(4));
            let mut v = [0u8; 8];
            v.copy_from_slice(take!(8));
            let mut sl = [0u8; 4];
            sl.copy_from_slice(take!(4));
            let slen = u32::from_le_bytes(sl) as usize;
            let script = take!(slen).to_vec();
            spent.push((
                OutPoint {
                    txid: Hash32(txid),
                    index: u32::from_le_bytes(ix),
                },
                TxOut {
                    value: Amount(u64::from_le_bytes(v)),
                    script_pubkey: script,
                },
            ));
        }
        // Coinbase sections are optional for backward compatibility with undo
        // files written before coinbase maturity existed.
        let (coinbase_created, coinbase_spent) = if pos < buf.len() {
            let mut cu2 = [0u8; 4];
            cu2.copy_from_slice(take!(4));
            let ncc = u32::from_le_bytes(cu2) as usize;
            let mut cc = Vec::new();
            for _ in 0..ncc {
                let mut txid = [0u8; 32];
                txid.copy_from_slice(take!(32));
                let mut ix = [0u8; 4];
                ix.copy_from_slice(take!(4));
                let mut hh = [0u8; 8];
                hh.copy_from_slice(take!(8));
                cc.push((
                    OutPoint {
                        txid: Hash32(txid),
                        index: u32::from_le_bytes(ix),
                    },
                    u64::from_le_bytes(hh),
                ));
            }
            let mut cu3 = [0u8; 4];
            cu3.copy_from_slice(take!(4));
            let ncs = u32::from_le_bytes(cu3) as usize;
            let mut cs = Vec::new();
            for _ in 0..ncs {
                let mut txid = [0u8; 32];
                txid.copy_from_slice(take!(32));
                let mut ix = [0u8; 4];
                ix.copy_from_slice(take!(4));
                let mut hh = [0u8; 8];
                hh.copy_from_slice(take!(8));
                cs.push((
                    OutPoint {
                        txid: Hash32(txid),
                        index: u32::from_le_bytes(ix),
                    },
                    u64::from_le_bytes(hh),
                ));
            }
            (cc, cs)
        } else {
            (Vec::new(), Vec::new())
        };
        map.insert(
            Hash32(h),
            UndoData {
                created,
                spent,
                coinbase_created,
                coinbase_spent,
            },
        );
    }
    map
}

/// File-backed chain store. Wraps `MemoryStore` (reusing all trait logic
/// unchanged) and persists to the multi-file, prunable layout described above.
pub struct FileStore {
    base: PathBuf,
    inner: MemoryStore,
    idx: HashMap<u64, (u64, u64, bool)>,
    prune: Option<PruneConfig>,
    last_compacted: u64,
}

impl FileStore {
    /// Open (or create) the store under `base` (a directory). Loads existing
    /// files if present; otherwise starts empty. `prune` enables block-body
    /// pruning when `Some`.
    pub fn open(base: impl Into<PathBuf>, prune: Option<PruneConfig>) -> Result<Self, String> {
        let base = base.into();
        fs::create_dir_all(&base).map_err(|e| format!("cannot create dir: {e}"))?;
        let idx_path = base.join("chain.idx");
        let idx = if idx_path.exists() {
            let b = fs::read(&idx_path).map_err(|e| format!("cannot read index: {e}"))?;
            parse_index(&b)?
        } else {
            HashMap::new()
        };
        let mut inner = MemoryStore::new();
        if base.join("chain.dat").exists() {
            let mut f = File::open(base.join("chain.dat"))
                .map_err(|e| format!("cannot open chain: {e}"))?;
            for (_h, (off, _len, _hb)) in idx.iter() {
                let (_hh, _has_body, header, txs) = read_block_record(&mut f, *off)
                    .map_err(|e| format!("cannot read block: {e}"))?;
                let block = Block { header, txs };
                let hash = block.block_hash();
                inner.blocks.insert(hash, block);
                inner.height.insert(hash, _hh);
            }
        }
        let tip = if base.join("tip.dat").exists() {
            let b = fs::read(base.join("tip.dat")).map_err(|e| format!("cannot read tip: {e}"))?;
            if b.len() == 32 && b != [0u8; 32] {
                let mut t = [0u8; 32];
                t.copy_from_slice(&b);
                Some(Hash32(t))
            } else {
                None
            }
        } else {
            None
        };
        inner.tip = tip;
        if base.join("utxo.dat").exists() {
            let b =
                fs::read(base.join("utxo.dat")).map_err(|e| format!("cannot read utxos: {e}"))?;
            inner.utxos = parse_utxos(&b)?;
        }
        if base.join("coinbase.dat").exists() {
            let b = fs::read(base.join("coinbase.dat"))
                .map_err(|e| format!("cannot read coinbase: {e}"))?;
            inner.coinbase = parse_coinbase(&b)?;
        }
        let best = inner.best_height();
        let last_compacted = best.saturating_sub(prune.as_ref().map(|p| p.keep_depth).unwrap_or(0));
        let mut fs = FileStore {
            base,
            inner,
            idx,
            prune,
            last_compacted,
        };
        // Restore restart-safe chain state (cumulative work, applied set, PoW
        // validity) and recorded undo data so reorganisations keep working.
        if fs.meta_path().exists() {
            let b = fs::read(fs.meta_path()).map_err(|e| format!("cannot read meta: {e}"))?;
            let (work, applied, pow_ok) = parse_meta(&b);
            fs.inner.work = work;
            fs.inner.applied = applied;
            fs.inner.pow_ok = pow_ok;
        }
        if fs.undo_path().exists() {
            let b = fs::read(fs.undo_path()).map_err(|e| format!("cannot read undo: {e}"))?;
            fs.inner.undo = parse_undo(&b);
        }
        Ok(fs)
    }

    fn chain_path(&self) -> PathBuf {
        self.base.join("chain.dat")
    }
    fn idx_path(&self) -> PathBuf {
        self.base.join("chain.idx")
    }
    fn utxo_path(&self) -> PathBuf {
        self.base.join("utxo.dat")
    }
    fn coinbase_path(&self) -> PathBuf {
        self.base.join("coinbase.dat")
    }
    fn tip_path(&self) -> PathBuf {
        self.base.join("tip.dat")
    }
    fn meta_path(&self) -> PathBuf {
        self.base.join("chainmeta.dat")
    }
    fn undo_path(&self) -> PathBuf {
        self.base.join("undo.dat")
    }

    fn write_index(&self) -> Result<(), String> {
        write_index(&self.idx_path(), &self.idx).map_err(|e| format!("cannot write index: {e}"))
    }

    fn write_utxos(&self) -> Result<(), String> {
        write_utxos(
            &self.utxo_path(),
            &self.inner.utxos,
        )
        .map_err(|e| format!("cannot write utxos: {e}"))
    }

    fn write_coinbase(&self) -> Result<(), String> {
        write_coinbase(&self.coinbase_path(), &self.inner.coinbase)
            .map_err(|e| format!("cannot write coinbase: {e}"))
    }

    fn write_tip(&self) -> Result<(), String> {
        let bytes = self.inner.tip.map(|h| h.0).unwrap_or([0u8; 32]);
        fs::write(self.tip_path(), bytes).map_err(|e| format!("cannot write tip: {e}"))
    }

    fn write_meta(&self) -> Result<(), String> {
        write_meta(
            &self.meta_path(),
            &self.inner.work,
            &self.inner.applied,
            &self.inner.pow_ok,
        )
        .map_err(|e| format!("cannot write meta: {e}"))
    }

    fn write_undo(&self) -> Result<(), String> {
        write_undo(&self.undo_path(), &self.inner.undo)
            .map_err(|e| format!("cannot write undo: {e}"))
    }

    /// Physically drop block bodies older than `keep_depth` from `chain.dat`,
    /// keeping headers. Triggered every `keep_depth` blocks while pruning.
    fn compact(&mut self, keep_depth: u64) -> Result<(), String> {
        let best = self.inner.best_height();
        let cutoff = best.saturating_sub(keep_depth);
        let mut heights: Vec<u64> = self.idx.keys().copied().collect();
        heights.sort_unstable();
        let rev: HashMap<u64, Hash32> = self.inner.height.iter().map(|(h, n)| (*n, *h)).collect();
        let pairs: Vec<(u64, Hash32)> = heights
            .iter()
            .filter_map(|&h| rev.get(&h).map(|hash| (h, *hash)))
            .collect();
        drop(rev);
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.chain_path())
            .map_err(|e| format!("cannot open chain: {e}"))?;
        let mut new_idx = HashMap::new();
        for (h, hash) in &pairs {
            let block = &self.inner.blocks[hash];
            let keep_body = *h > cutoff;
            let (off, end) = write_block_record(&mut f, *h, keep_body, &block.header, &block.txs)
                .map_err(|e| format!("cannot write block: {e}"))?;
            new_idx.insert(*h, (off, end - off, keep_body));
        }
        drop(f);
        self.idx = new_idx;
        self.write_index()?;
        self.last_compacted = cutoff;
        // Drop pruned bodies from memory too, so RAM stays bounded.
        for (h, hash) in &pairs {
            if *h <= cutoff {
                if let Some(b) = self.inner.blocks.get_mut(hash) {
                    b.txs.clear();
                }
            }
        }
        Ok(())
    }

    /// Write a *snapshot* of the current live state (UTXO set,
    /// coinbase heights, tip, chain work) plus a trustless `snapshot.meta`
    /// describing it. A bootstrapping node can `load_snapshot` and verify the
    /// state purely from `snapshot.meta.state_root` (recomputed over the loaded
    /// set) — no block history is needed. Only the tip block body is retained so
    /// the node can still validate the *next* block's header.
    pub fn save_snapshot(&self, dir: &Path) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| format!("cannot create snapshot dir: {e}"))?;
        self.snapshot_write_state(dir)?;
        let tip = self
            .inner
            .tip()
            .ok_or_else(|| "cannot snapshot an empty store".to_string())?;
        let meta = SnapshotMeta {
            magic: *SNAPSHOT_MAGIC,
            version: SNAPSHOT_VERSION,
            height: self.inner.height_of(&tip).unwrap_or(0),
            block_hash: tip,
            work: self.inner.work_of(&tip),
            state_root: state::StateStore::root(&self.inner),
        };
        fs::write(dir.join("snapshot.meta"), meta.encode())
            .map_err(|e| format!("cannot write snapshot.meta: {e}"))?;
        Ok(())
    }

    /// Load a previously saved snapshot. After loading the state, the committed
    /// `state_root` is recomputed from the loaded set and compared to
    /// `snapshot.meta.state_root`; a mismatch means the snapshot is corrupt or
    /// tampered and is rejected. This is the trustless check: we verify by
    /// *loading* the state and recomputing, never by trusting the file's bytes.
    pub fn load_snapshot(dir: impl Into<PathBuf>, params: &ChainParams) -> Result<Self, String> {
        let base = dir.into();
        let fs = FileStore::open(base.clone(), None)?;
        let meta = SnapshotMeta::decode(
            &fs::read(base.join("snapshot.meta"))
                .map_err(|e| format!("cannot read snapshot.meta: {e}"))?,
        )?;
        if state::StateStore::root(&fs.inner) != meta.state_root {
            return Err("snapshot state_root mismatch: snapshot is corrupt or untrustworthy".into());
        }
        // Checkpoint-bounded trust: a snapshot may only be trusted if its tip is
        // consistent with the highest checkpoint at or below its height. With an
        // empty checkpoint list (a new testnet) this is a no-op. Once checkpoints
        // exist, a snapshot whose tip diverges from the pinned chain is rejected —
        // the snapshot shortcuts history, it does not replace the finality that
        // checkpoints provide.
        if let Some(cp) = params.checkpoint_at_or_below(meta.height) {
            if meta.block_hash != cp {
                return Err(format!(
                    "snapshot tip does not match checkpoint at height {}; snapshot is untrustworthy",
                    meta.height
                ));
            }
        }
        Ok(fs)
    }

    fn snapshot_write_state(&self, dir: &Path) -> Result<(), String> {
        write_utxos(
            &dir.join("utxo.dat"),
            &self.inner.utxos,
        )
        .map_err(|e| format!("snapshot utxo: {e}"))?;
        write_coinbase(&dir.join("coinbase.dat"), &self.inner.coinbase)
            .map_err(|e| format!("snapshot coinbase: {e}"))?;
        write_meta(
            &dir.join("chainmeta.dat"),
            &self.inner.work,
            &self.inner.applied,
            &self.inner.pow_ok,
        )
        .map_err(|e| format!("snapshot meta: {e}"))?;
        let tip_bytes = self.inner.tip().map(|h| h.0).unwrap_or([0u8; 32]);
        fs::write(dir.join("tip.dat"), tip_bytes).map_err(|e| format!("snapshot tip: {e}"))?;
        // Keep only the tip block body so the node can validate the next block.
        let mut f =
            File::create(dir.join("chain.dat")).map_err(|e| format!("snapshot chain: {e}"))?;
        let mut idx = HashMap::new();
        if let Some(tip) = self.inner.tip() {
            if let Some(b) = self.inner.blocks.get(&tip) {
                let h = self.inner.height_of(&tip).unwrap_or(0);
                let (off, end) = write_block_record(&mut f, h, true, &b.header, &b.txs)
                    .map_err(|e| format!("snapshot chain: {e}"))?;
                idx.insert(h, (off, end - off, true));
            }
        }
        write_index(&dir.join("chain.idx"), &idx).map_err(|e| format!("snapshot index: {e}"))?;
        Ok(())
    }
}

impl BlockStore for FileStore {
    fn put_block(&mut self, block: &Block) -> Result<(), String> {
        self.inner.put_block(block)?;
        let height = block.header.height;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.chain_path())
            .map_err(|e| format!("cannot open chain: {e}"))?;
        let (off, end) = write_block_record(&mut f, height, true, &block.header, &block.txs)
            .map_err(|e| format!("cannot write block: {e}"))?;
        drop(f);
        self.idx.insert(height, (off, end - off, true));
        self.write_index()?;
        if self.prune.is_some() {
            let best = self.inner.best_height();
            let kd = self.prune.as_ref().unwrap().keep_depth;
            if best > 0 && best - self.last_compacted >= kd {
                self.compact(kd)?;
            }
        }
        Ok(())
    }
    fn get_block(&self, hash: &Hash32) -> Option<Block> {
        self.inner.get_block(hash)
    }
    fn has_block(&self, hash: &Hash32) -> bool {
        self.inner.has_block(hash)
    }
}

impl ChainStore for FileStore {
    fn set_tip(&mut self, hash: Hash32, height: u64) {
        self.inner.set_tip(hash, height);
        let _ = self.write_tip();
    }
    fn tip(&self) -> Option<Hash32> {
        self.inner.tip()
    }
    fn height_of(&self, hash: &Hash32) -> Option<u64> {
        self.inner.height_of(hash)
    }
}

impl UtxoStore for FileStore {
    fn add_utxo(&mut self, outpoint: OutPoint, output: TxOut) {
        self.inner.add_utxo(outpoint, output);
        let _ = self.write_utxos();
    }
    fn spend_utxo(&mut self, outpoint: &OutPoint) -> Result<TxOut, String> {
        let r = self.inner.spend_utxo(outpoint);
        if r.is_ok() {
            let _ = self.write_utxos();
            let _ = self.write_coinbase();
        }
        r
    }
    fn utxo(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.inner.utxo(outpoint)
    }
    fn remove_utxo(&mut self, outpoint: &OutPoint) {
        self.inner.remove_utxo(outpoint);
        let _ = self.write_utxos();
    }
    fn find_by_commit(&self, commit: &[u8; 20]) -> Option<OutPoint> {
        self.inner.find_by_commit(commit)
    }
    fn iter_utxos(&self) -> Vec<(OutPoint, TxOut)> {
        self.inner.iter_utxos()
    }
}

impl SpendStore for FileStore {
    fn mark_coinbase(&mut self, op: &OutPoint, height: u64) {
        self.inner.mark_coinbase(op, height);
        let _ = self.write_coinbase();
    }
    fn coinbase_height(&self, op: &OutPoint) -> Option<u64> {
        self.inner.coinbase_height(op)
    }

    fn begin_block(&mut self, hash: Hash32) {
        self.inner.begin_block(hash);
    }
    fn end_block(&mut self) {
        self.inner.end_block();
        let _ = self.write_undo();
    }
    fn get_undo(&self, hash: &Hash32) -> Option<UndoData> {
        self.inner.get_undo(hash)
    }
    fn disconnect(&mut self, hash: &Hash32) {
        self.inner.disconnect(hash);
        let _ = self.write_utxos();
        let _ = self.write_coinbase();
        let _ = self.write_undo();
    }
    fn remember_pow(&mut self, hash: Hash32) {
        self.inner.remember_pow(hash);
        let _ = self.write_meta();
    }
    fn is_pow_valid(&self, hash: &Hash32) -> bool {
        self.inner.is_pow_valid(hash)
    }
    fn set_work(&mut self, hash: Hash32, work: u128) {
        self.inner.set_work(hash, work);
        let _ = self.write_meta();
    }
    fn work_of(&self, hash: &Hash32) -> u128 {
        self.inner.work_of(hash)
    }
    fn mark_applied(&mut self, hash: Hash32) {
        self.inner.mark_applied(hash);
        let _ = self.write_meta();
    }
    fn is_applied(&self, hash: &Hash32) -> bool {
        self.inner.is_applied(hash)
    }
    fn best_tip_by_work(&self) -> Option<Hash32> {
        self.inner.best_tip_by_work()
    }
    fn parent_of(&self, hash: &Hash32) -> Option<Hash32> {
        self.inner.parent_of(hash)
    }
}

impl state::StateStore for FileStore {
    fn get_utxo(&self, op: &OutPoint) -> Option<state::UtxoEntry> {
        self.inner.get_utxo(op)
    }
    fn put_utxo(&mut self, op: OutPoint, entry: state::UtxoEntry) {
        self.inner.put_utxo(op, entry);
        let _ = self.write_utxos();
        let _ = self.write_coinbase();
    }
    fn remove_utxo(&mut self, op: &OutPoint) {
        let _ = self.spend_utxo(op);
    }
    fn root(&self) -> [u8; 32] {
        self.inner.root()
    }
    fn iter_utxos(&self) -> Vec<(OutPoint, state::UtxoEntry)> {
        state::StateStore::iter_utxos(&self.inner)
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use litc_primitives::{
        merkle_root, Amount, Block, BlockHeader, Hash32, OutPoint, SignatureScheme, Transaction,
        TxIn, TxOut,
    };
    use std::fs;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("litc_snap_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn snapshot_roundtrip_and_tamper_rejected() {
        let dir = tmp_dir("rt");
        let mut s = FileStore::open(dir.join("live"), None).unwrap();

        // Populate a live state.
        let op = OutPoint {
            txid: Hash32([1u8; 32]),
            index: 0,
        };
        s.add_utxo(
            op.clone(),
            TxOut {
                value: Amount(5 * 100_000_000),
                script_pubkey: vec![9u8; 20],
            },
        );
        s.mark_coinbase(&op, 0);
        let op2 = OutPoint {
            txid: Hash32([2u8; 32]),
            index: 1,
        };
        s.add_utxo(
            op2.clone(),
            TxOut {
                value: Amount(100_000_000),
                script_pubkey: vec![8u8; 20],
            },
        );

        // Tip block body, so a fast-synced node can still validate the *next*
        // block's header.
        let header = BlockHeader {
            version: 1,
            prev_block: Hash32([0u8; 32]),
            merkle_root: Hash32([0u8; 32]),
            state_root: Hash32([0u8; 32]),
            timestamp: 0,
            height: 100,
            epoch_seed: Hash32([0u8; 32]),
            nonce: 0,
        };
        let block = Block {
            header,
            txs: vec![],
        };
        let tip = block.block_hash();
        s.put_block(&block).unwrap();
        s.set_tip(tip, 100);
        s.set_work(tip, 1_000_000);

        // Save and reload; the recomputed root must match and the tip must be
        // carried so the next block can be validated.
        let snap = dir.join("snap");
        s.save_snapshot(&snap).unwrap();
        let loaded = FileStore::load_snapshot(&snap, &ChainParams::testnet()).unwrap();
        assert_eq!(state::StateStore::root(&loaded), state::StateStore::root(&s));
        assert_eq!(loaded.tip(), Some(tip));
        assert_eq!(loaded.height_of(&tip), Some(100));
        assert!(loaded.get_block(&tip).is_some());

        // Tamper with the UTXO set: the trustless check must reject the snapshot
        // (the stored state_root no longer matches the loaded state).
        let mut bytes = fs::read(snap.join("utxo.dat")).unwrap();
        bytes[5] ^= 0xFF; // mutate a txid byte (still parses, changes the set)
        fs::write(snap.join("utxo.dat"), &bytes).unwrap();
        assert!(FileStore::load_snapshot(&snap, &ChainParams::testnet()).is_err());
    }

    /// End-to-end fast-sync: build a chain of blocks on a live store, snapshot
    /// it, then load the snapshot into a *fresh* store and continue applying
    /// blocks. The fast-synced node must pick up exactly where the snapshot
    /// left off (same UTXO set, same tip) and accept the next block.
    #[test]
    fn fast_sync_continues_chain() {
        let dir = tmp_dir("e2e");
        let mut live = FileStore::open(dir.join("live"), None).unwrap();

        // Fund a spendable UTXO at height 0 (coinbase, so it must mature).
        let op = OutPoint {
            txid: Hash32([1u8; 32]),
            index: 0,
        };
        live.add_utxo(
            op.clone(),
            TxOut {
                value: Amount(5 * 100_000_000),
                script_pubkey: vec![9u8; 20],
            },
        );
        live.mark_coinbase(&op, 0);
        live.set_tip(Hash32([0u8; 32]), 0);
        live.set_work(Hash32([0u8; 32]), 1);

        // "Mine" a chain of blocks simply by recording tip transitions and the
        // evolving UTXO set. Each block spends the funded output forward.
        let mut tip = Hash32([0u8; 32]);
        let mut height = 0u64;
        for i in 1..=5u64 {
            let seed = i.to_be_bytes();
            let mut pkh = [0u8; 20];
            pkh[..8].copy_from_slice(&seed);
            let tx = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    prevout: op.clone(),
                    scheme: SignatureScheme::Mldsa2,
                    script_sig: vec![],
                    sequence: 0xFFFF_FFFF,
                }],
                outputs: vec![TxOut {
                    value: Amount(1_000_000),
                    script_pubkey: pkh.to_vec(),
                }],
                lock_time: 0,
            };
            let header = BlockHeader {
                version: 1,
                prev_block: tip,
                merkle_root: merkle_root(std::slice::from_ref(&tx)),
                state_root: Hash32([0u8; 32]),
                timestamp: i,
                height: i,
                epoch_seed: Hash32([0u8; 32]),
                nonce: i,
            };
            let block = Block {
                header,
                txs: vec![tx],
            };
            let h = block.block_hash();
            live.put_block(&block).unwrap();
            live.set_tip(h, i);
            live.set_work(h, i as u128 + 1);
            // Move the UTXO forward to the new output so the snapshot has a live tip.
            live.remove_utxo(&op);
            let new_op = OutPoint {
                txid: h,
                index: 0,
            };
            live.add_utxo(
                new_op.clone(),
                TxOut {
                    value: Amount(1_000_000),
                    script_pubkey: pkh.to_vec(),
                },
            );
            tip = h;
            height = i;
        }

        // Snapshot the live state.
        let snap = dir.join("snap");
        live.save_snapshot(&snap).unwrap();

        // Fresh store boots from the snapshot (trustless verify on load).
        let mut synced = FileStore::load_snapshot(&snap, &ChainParams::testnet()).unwrap();
        assert_eq!(synced.tip(), Some(tip));
        assert_eq!(synced.height_of(&tip), Some(height));
        // A live output must have carried over.
        let carried = OutPoint {
            txid: tip,
            index: 0,
        };
        assert!(synced.utxo(&carried).is_some());

        // Continuing the chain past the snapshot works: append block 6.
        let new_op = OutPoint {
            txid: tip,
            index: 0,
        };
        let seed = 6u64.to_be_bytes();
        let mut pkh = [0u8; 20];
        pkh[..8].copy_from_slice(&seed);
        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prevout: new_op.clone(),
                scheme: SignatureScheme::Mldsa2,
                script_sig: vec![],
                sequence: 0xFFFF_FFFF,
            }],
            outputs: vec![TxOut {
                value: Amount(500_000),
                script_pubkey: pkh.to_vec(),
            }],
            lock_time: 0,
        };
        let header = BlockHeader {
            version: 1,
            prev_block: tip,
            merkle_root: merkle_root(std::slice::from_ref(&tx)),
            state_root: Hash32([0u8; 32]),
            timestamp: 6,
            height: 6,
            epoch_seed: Hash32([0u8; 32]),
            nonce: 6,
        };
        let block = Block {
            header,
            txs: vec![tx],
        };
        let h = block.block_hash();
        synced.put_block(&block).unwrap();
        synced.set_tip(h, 6);
        synced.set_work(h, 7);
        assert_eq!(synced.tip(), Some(h));
        assert_eq!(synced.height_of(&h), Some(6));
    }
}
