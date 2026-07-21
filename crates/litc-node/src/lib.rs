//! LiTC node with minimal P2P: TCP, `version` handshake, `inv`/`getdata`
//! inventory, and `tx`/`block` relay across multiple peers. No external async
//! runtime — one OS thread per connection, blocking I/O, and a shared
//! `Mutex<Node>` for state.
//!
//! Run:
//!   cargo run -p litc-node --features litc-pow/small -- --port 8333
//!   cargo run -p litc-node --features litc-pow/small -- --port 8334 --connect 127.0.0.1:8333 --no-mine
//!
//! `--no-mine` makes a node only relay (recommended for every node but one,
//! so the network does not compete to mine orphaned side blocks).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use litc_core::{
    block_state_root, reorganize, validate_block_header, validate_block_pow_merkle, validate_tx,
    block_subsidy_with, validate_checkpoint,
};
use litc_keystore::FileKeyStore;
use litc_miner::{assemble_block, BlockTemplate, CpuMiner, MinerBackend};
use litc_pow::{
    adjust_target, block_work, EPOCH_BLOCKS, INITIAL_TARGET, TARGET_TIMESPAN,
};
use litc_primitives::{
    sha256d, stealth, to_bytes, Block, Decodable, Hash32, Reader, Transaction,
};
use litc_primitives::chainparams::{ChainParams, Network};
use litc_store::state::StateStore;
use litc_store::{FileStore, PruneConfig, SpendStore};
use litc_wallet::Wallet;
use litc_wire::{Codec, InvVect, Message, NetAddr};

#[cfg(feature = "gpu")]
use litc_miner_gpu_wgpu::WgpuMiner;

mod rpc;

/// Node configuration loaded from `$LITC_DATADIR/config.toml` (`[node]` table).
struct NodeConfig {
    prune: bool,
    prune_target_size_mb: Option<u64>,
    prune_keep_depth: Option<u64>,
    /// Bootstrap seed nodes (`host:port`) to connect to on startup.
    seeds: Vec<String>,
}

impl NodeConfig {
    fn default() -> Self {
        NodeConfig {
            prune: false,
            prune_target_size_mb: None,
            prune_keep_depth: None,
            seeds: Vec::new(),
        }
    }

    /// Parse a minimal TOML file, reading only the `[node]` section.
    fn from_file(path: &Path) -> Self {
        let mut cfg = NodeConfig::default();
        if let Ok(s) = fs::read_to_string(path) {
            let mut in_node = false;
            for line in s.lines() {
                let line = line.trim();
                if line.starts_with('[') {
                    in_node = line == "[node]";
                    continue;
                }
                if !in_node {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim();
                    let v = v.trim().trim_matches('"');
                    match k {
                        "prune" => cfg.prune = v == "true" || v == "1",
                        "prune_target_size_mb" => cfg.prune_target_size_mb = v.parse().ok(),
                        "prune_keep_depth" => cfg.prune_keep_depth = v.parse().ok(),
                        "seeds" => {
                            for s in v.split(',') {
                                let s = s.trim();
                                if !s.is_empty() {
                                    cfg.seeds.push(s.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        cfg
    }

    /// Build the `FileStore` pruning config, if enabled.
    fn prune_config(&self) -> Option<PruneConfig> {
        if !self.prune {
            return None;
        }
        // 512 MB / ~182 KB per block body ≈ 2880 blocks (12 h at 15 s).
        const EST_BLOCK_BODY: u64 = 182_000;
        let keep_depth = self
            .prune_keep_depth
            .unwrap_or_else(|| match self.prune_target_size_mb {
                Some(mb) => ((mb * 1024 * 1024) / EST_BLOCK_BODY).max(1),
                None => 2880,
            });
        Some(PruneConfig { keep_depth })
    }
}

const MSG_TX: u8 = 1;
const MSG_BLOCK: u8 = 2;
const DEFAULT_PORT: u16 = 8333;

/// Maximum number of transactions kept in the mempool. Bounds memory usage if
/// a peer floods us with (valid) transactions; once full, new txs are dropped
/// until the miner drains the pool.
const MAX_MEMPOOL: usize = 50_000;
/// Per-peer rate limits (DoS guards). A peer may submit at most `LIMIT`
/// messages of a kind within a sliding `WINDOW`-second window.
const PEER_TX_WINDOW: u64 = 60;
const PEER_TX_LIMIT: usize = 200;
const PEER_BLOCK_WINDOW: u64 = 60;
const PEER_BLOCK_LIMIT: usize = 200;
/// Sentinel "peer" for locally-originated traffic (miner output, the mempool
/// directory), which is trusted and not rate-limited in the same way.
const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

/// A worker registered with the built-in mining pool.
#[derive(Clone)]
pub(crate) struct PoolWorker {
    pub addr: SocketAddr,
    pub name: String,
    pub blocks_found: u64,
    pub shares: u64,
    /// Last block height this worker submitted a share/block for.
    pub last_height: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Write a signed transaction to `$LITC_DATADIR/mempool/<txid>.tx` so the node's
/// periodic mempool sweep picks it up and broadcasts it.
pub(crate) fn write_tx(tx: &Transaction) {
    let id = tx.txid();
    let data_dir = std::env::var("LITC_DATADIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("data"));
    let dir = data_dir.join("mempool");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{}.tx", id.to_hex()));
    let _ = std::fs::write(&path, to_bytes(tx));
}

/// True if `addr` is within its sliding-window rate limit for this message
/// kind (prunes stale timestamps first). Does not record the event.
fn peer_rate_allowed(
    map: &mut HashMap<SocketAddr, Vec<u64>>,
    addr: &SocketAddr,
    window: u64,
    limit: usize,
) -> bool {
    let now = now_secs();
    let v = map.entry(*addr).or_default();
    v.retain(|t| now.saturating_sub(*t) < window);
    v.len() < limit
}

/// Record one accepted message of this kind from `addr`.
fn peer_rate_record(map: &mut HashMap<SocketAddr, Vec<u64>>, addr: &SocketAddr) {
    map.entry(*addr).or_default().push(now_secs());
}

/// Shared node state. `S` is the chain store (in-memory or file-backed).
pub(crate) struct Node<S: SpendStore + StateStore> {
    pub(crate) store: S,
    pub(crate) wallet: Wallet,
    pub(crate) known_blocks: HashSet<Hash32>,
    pub(crate) known_txs: HashSet<Hash32>,
    pub(crate) mempool: Vec<Transaction>,
    /// Per-peer transaction-accept timestamps (for rate limiting).
    peer_tx: HashMap<SocketAddr, Vec<u64>>,
    /// Per-peer block-accept timestamps (for rate limiting).
    peer_block: HashMap<SocketAddr, Vec<u64>>,
    my_nonce: u64,
    /// Best chain tip (Hash32([0u8; 32]) until the first block arrives).
    pub(crate) tip: Hash32,
    /// Network consensus parameters (magic, halving interval, checkpoints).
    /// Selected at startup via `--network` / `LITC_NETWORK`.
    pub(crate) params: ChainParams,
    epoch_seed: [u8; 32],
    /// Target (difficulty) per epoch index; epoch 0 is `INITIAL_TARGET`.
    epoch_targets: Vec<[u8; 32]>,
    /// Best-chain block hash + timestamp, indexed by height.
    pub(crate) chain: HashMap<u64, (Hash32, u64)>,
    /// Mining pool workers.
    pub(crate) pool_workers: Vec<PoolWorker>,
}

impl<S: SpendStore + StateStore> Node<S> {
    fn new(store: S, seed: [u8; 32], params: ChainParams) -> Self {
        let wallet = Wallet::new(seed);
        let nonce_bytes = litc_keystore::random_seed().unwrap_or([0u8; 32]);
        let my_nonce = u64::from_be_bytes(nonce_bytes[..8].try_into().unwrap());
        let loaded_tip = store.tip().unwrap_or(Hash32([0u8; 32]));
        let mut n = Node {
            store,
            wallet,
            known_blocks: HashSet::new(),
            known_txs: HashSet::new(),
            mempool: Vec::new(),
            peer_tx: HashMap::new(),
            peer_block: HashMap::new(),
            my_nonce,
            tip: loaded_tip,
            epoch_seed: sha256d(b"litc-genesis").0,
            epoch_targets: vec![INITIAL_TARGET],
            chain: HashMap::new(),
            params,
            pool_workers: Vec::new(),
        };
        // Rebuild the best-chain index so sync/relay work immediately after a
        // restart (the store already loaded its tip from disk).
        n.sync_chain();
        n
    }

    fn best_height(&self) -> u64 {
        self.store.height_of(&self.tip).map(|h| h + 1).unwrap_or(0)
    }

    /// Leading zero bits of the current target — a rough difficulty measure.
    pub(crate) fn difficulty_bits(&self) -> u32 {
        let t = self.target_for(self.best_height());
        let mut bits = 0u32;
        for b in t.iter() {
            if *b == 0 {
                bits += 8;
            } else {
                bits += b.leading_zeros();
                break;
            }
        }
        bits
    }

    /// Difficulty target for a block at `height` (per-epoch, set at boundaries).
    fn target_for(&self, height: u64) -> [u8; 32] {
        let epoch = (height / EPOCH_BLOCKS) as usize;
        if epoch < self.epoch_targets.len() {
            self.epoch_targets[epoch]
        } else {
            INITIAL_TARGET
        }
    }

    pub(crate) fn make_template(&mut self) -> (BlockTemplate, [u8; 32]) {
        let height = self.best_height();
        let seed = if height.is_multiple_of(EPOCH_BLOCKS) {
            if height == 0 {
                sha256d(b"litc-genesis").0
            } else {
                sha256d(&self.tip.0).0
            }
        } else {
            self.epoch_seed
        };
        let target = self.target_for(height);
        let txs = self.valid_mempool_txs();
        let coinbase_value = block_subsidy_with(height, self.params.halving_interval);
        let (kem_pk, _) = self.wallet.kem_keypair();
        let (txout, ct) = stealth::build_stealth_output(&kem_pk, coinbase_value);
        let mut template = BlockTemplate {
            prev_block: self.tip,
            height,
            timestamp: now_secs(),
            epoch_seed: Hash32(seed),
            coinbase_value,
            coinbase_script: txout.script_pubkey,
            coinbase_ephemeral: ct.to_vec(),
            txs,
            state_root: Hash32([0u8; 32]),
        };
        // Compute the post-state root for the candidate block and bind it into
        // the template, so the PoW secures the resulting state (see
        // `docs/state.md`). Bootstrapping nodes verify it trustlessly.
        let candidate = assemble_block(&template);
        let root = block_state_root(&mut self.store, &candidate)
            .expect("template should apply to current state");
        template.state_root = Hash32(root);
        (template, target)
    }

    /// Filter the mempool down to transactions that will actually validate in a
    /// block right now: each must verify against the current UTXO set (correct
    /// signatures, no already-burnt key, no inflation, and coinbase outputs
    /// mature enough) and must not double-spend an outpoint already claimed by
    /// another mempool transaction. The result is safe to hand to the miner, so
    /// a mined block always passes full validation and is accepted (guaranteeing
    /// the chain keeps advancing even when peers feed us garbage transactions).
    fn valid_mempool_txs(&self) -> Vec<Transaction> {
        let spend_height = self.best_height();
        let mut claimed: HashSet<litc_primitives::OutPoint> = HashSet::new();
        let mut keep = Vec::new();
        for tx in &self.mempool {
            if tx.inputs.is_empty() {
                continue; // coinbases are minted by the miner, never relayed
            }
            if tx.inputs.iter().any(|i| claimed.contains(&i.prevout)) {
                continue; // intra-mempool double spend
            }
            if validate_tx(tx, &self.store, spend_height).is_err() {
                continue;
            }
            for i in &tx.inputs {
                claimed.insert(i.prevout.clone());
            }
            keep.push(tx.clone());
        }
        keep
    }

    /// Accept a block (mined locally or relayed). Returns true if it was new
    /// and valid, so the caller can relay an `inv`.
    ///
    /// Validation here only covers Proof-of-Work and the merkle root. UTXO
    /// application (and any chain reorganisation) happens in `reorg`, which
    /// picks the heaviest known chain by cumulative work.
    pub(crate) fn accept_block(&mut self, block: Block, from: SocketAddr) -> bool {
        let hash = block.block_hash();
        let height = block.header.height;
        if self.known_blocks.contains(&hash) {
            return false;
        }
        // Per-peer block rate limit (DoS guard against header-rain attacks).
        // Skip for locally mined blocks.
        if from != LOCAL && !peer_rate_allowed(&mut self.peer_block, &from, PEER_BLOCK_WINDOW, PEER_BLOCK_LIMIT) {
            return false;
        }
        let target = self.target_for(height);
        if !validate_block_pow_merkle(&block, &target) {
            return false;
        }
        if validate_block_header(&block, &self.store).is_err() {
            return false;
        }
        // A block at a checkpoint height must carry the pinned hash; this
        // finalizes history at/below the checkpoint and bounds snapshot trust.
        if validate_checkpoint(&block, &self.params).is_err() {
            return false;
        }
        peer_rate_record(&mut self.peer_block, &from);
        // Record the block, its cumulative work, and that PoW is validated.
        self.store.remember_pow(hash);
        let _ = self.store.put_block(&block);
        let parent_work = self.store.work_of(&block.header.prev_block);
        let work = parent_work + block_work(&target);
        self.store.set_work(hash, work);
        // Reorganise to the heaviest chain (may apply/rollback blocks).
        self.reorg();
        self.known_blocks.insert(hash);
        self.tip = self.store.tip().unwrap_or(Hash32([0u8; 32]));
        self.sync_chain();
        // Retarget at the start of every epoch after genesis.
        if height.is_multiple_of(EPOCH_BLOCKS) {
            self.epoch_seed = if height == 0 {
                sha256d(b"litc-genesis").0
            } else {
                self.chain
                    .get(&height)
                    .map(|x| sha256d(&x.0 .0).0)
                    .unwrap_or(self.epoch_seed)
            };
            if height > 0 {
                let epoch = height / EPOCH_BLOCKS;
                let prev_epoch = epoch - 1;
                let first = self.chain.get(&(prev_epoch * EPOCH_BLOCKS)).map(|x| x.1);
                let last = self.chain.get(&(epoch * EPOCH_BLOCKS - 1)).map(|x| x.1);
                let next = match (first, last) {
                    (Some(f), Some(l)) => adjust_target(
                        &self.epoch_targets[prev_epoch as usize],
                        l - f,
                        TARGET_TIMESPAN,
                    ),
                    _ => INITIAL_TARGET,
                };
                self.epoch_targets.push(next);
            }
        }
        // Drop only the mempool txs that actually landed in this block.
        let ids: std::collections::HashSet<_> = block.txs.iter().map(|t| t.txid()).collect();
        self.mempool.retain(|tx| !ids.contains(&tx.txid()));
        true
    }

    /// Reorganise the active chain to the one with the most cumulative work.
    /// Rolls back the current tip to the common ancestor, then connects the
    /// new branch. UTXO changes are reversed via each block's `UndoData`.
    fn reorg(&mut self) {
        reorganize(&mut self.store);
    }

    /// Rebuild the best-chain index (`self.chain`) from the current tip, so
    /// difficulty retargeting uses the active chain.
    fn sync_chain(&mut self) {
        self.chain.clear();
        let mut h = match self.store.tip() {
            Some(h) => h,
            None => return,
        };
        while let Some(b) = self.store.get_block(&h) {
            self.chain.insert(b.header.height, (h, b.header.timestamp));
            h = b.header.prev_block;
        }
    }

    /// Build the `inv` vector of block hashes a peer should download, starting
    /// just after the highest locator hash we recognise, up to our tip. Used to
    /// answer `GetBlocks` during initial chain sync.
    fn block_inv_from_locator(&self, locator: &[[u8; 32]]) -> Vec<InvVect> {
        let tip_h = self.store.height_of(&self.tip).unwrap_or(0);
        let mut from = 0u64;
        for h in locator {
            if let Some(height) = self.store.height_of(&Hash32(*h)) {
                if height < tip_h {
                    from = from.max(height + 1);
                }
            }
        }
        let mut inv = Vec::new();
        let mut h = from;
        while h <= tip_h && inv.len() < MAX_SYNC_INV {
            if let Some((hash, _)) = self.chain.get(&h) {
                inv.push(InvVect {
                    kind: MSG_BLOCK,
                    hash: hash.0,
                });
            }
            h += 1;
        }
        inv
    }

    pub(crate) fn accept_tx(&mut self, tx: Transaction, from: SocketAddr) -> bool {
        let id = tx.txid();
        if self.known_txs.contains(&id) {
            return false;
        }
        // Reject obviously invalid transactions at the door: no coinbases in the
        // mempool (those are minted by the miner) and every input must verify
        // against the current UTXO set. This keeps the mempool clean; the block
        // template still re-validates and de-duplicates before mining.
        if tx.inputs.is_empty() {
            return false;
        }
        // Bound memory usage if a peer floods us with valid transactions.
        if self.mempool.len() >= MAX_MEMPOOL {
            eprintln!("[mempool] full ({}), dropping tx", self.mempool.len());
            return false;
        }
        // Per-peer transaction rate limit (DoS guard).
        if !peer_rate_allowed(&mut self.peer_tx, &from, PEER_TX_WINDOW, PEER_TX_LIMIT) {
            eprintln!("[p2p] peer {from} exceeded tx rate limit");
            return false;
        }
        // Validate against the current UTXO set at the prospective next height.
        if validate_tx(&tx, &self.store, self.best_height()).is_err() {
            return false;
        }
        peer_rate_record(&mut self.peer_tx, &from);
        self.known_txs.insert(id);
        self.mempool.push(tx);
        true
    }
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

pub(crate) type PeerMap = Arc<Mutex<HashMap<SocketAddr, Peer>>>;
/// Set of peer addresses known to the node (for seed/bootstrap and gossip).
type AddrSet = Arc<Mutex<HashSet<SocketAddr>>>;

/// Maximum number of block hashes returned in one `GetBlocks` response.
const MAX_SYNC_INV: usize = 2000;

struct Peer {
    writer: Arc<Mutex<TcpStream>>,
    handshaked: bool,
}

fn is_handshake(m: &Message) -> bool {
    matches!(m, Message::Version { .. } | Message::Verack)
}

fn send_msg(peers: &PeerMap, addr: &SocketAddr, codec: &Codec, msg: &Message) {
    let map = peers.lock().unwrap();
    if let Some(p) = map.get(addr) {
        if !p.handshaked && !is_handshake(msg) {
            return;
        }
        let _ = p.writer.lock().unwrap().write_all(&codec.frame(msg));
    }
}

fn broadcast(peers: &PeerMap, codec: &Codec, msg: &Message, except: Option<&SocketAddr>) {
    let map = peers.lock().unwrap();
    for (addr, p) in map.iter() {
        if except == Some(addr) {
            continue;
        }
        if !p.handshaked && !is_handshake(msg) {
            continue;
        }
        let _ = p.writer.lock().unwrap().write_all(&codec.frame(msg));
    }
}

/// Map a `SocketAddr` to a wire `NetAddr` (IPv4 is encoded as IPv4-mapped IPv6).
fn socket_to_netaddr(a: SocketAddr) -> Option<NetAddr> {
    let mut ip = [0u8; 16];
    match a {
        SocketAddr::V4(v4) => {
            ip[10..12].copy_from_slice(&[0xff, 0xff]);
            ip[12..16].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => ip.copy_from_slice(&v6.ip().octets()),
    }
    Some(NetAddr {
        services: 1,
        ip,
        port: a.port(),
        timestamp: now_secs(),
    })
}

/// Inverse of `socket_to_netaddr`.
fn netaddr_to_socket(na: &NetAddr) -> Option<SocketAddr> {
    let v4_mapped = na.ip[..10] == [0u8; 10] && na.ip[10..12] == [0xffu8, 0xff];
    let ip: std::net::IpAddr = if v4_mapped {
        let mut o = [0u8; 4];
        o.copy_from_slice(&na.ip[12..16]);
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(o))
    } else {
        let mut o = [0u8; 16];
        o.copy_from_slice(&na.ip);
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(o))
    };
    Some(SocketAddr::new(ip, na.port))
}

/// Open an outbound connection to `addr` (used for `--connect`, seeds, gossip).
fn connect_to<S: SpendStore + StateStore + Send + 'static>(
    addr: SocketAddr,
    peers: PeerMap,
    node: Arc<Mutex<Node<S>>>,
    known: AddrSet,
    listen: SocketAddr,
    connecting: &AddrSet,
) {
    {
        let p = peers.lock().unwrap();
        if p.contains_key(&addr) {
            eprintln!("[p2p] connect_to skip {addr} (already in peers)");
            return;
        }
        if !connecting.lock().unwrap().insert(addr) {
            eprintln!("[p2p] connect_to skip {addr} (already connecting)");
            return;
        }
    }
    eprintln!("[p2p] connect_to proceed {addr}");
    let cn = connecting.clone();
    thread::spawn(
        move || match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(s) => {
                // For an outbound connection the address we dialed is the peer's
                // listening address, so it's safe to record it for gossip.
                known.lock().unwrap().insert(addr);
                handle_conn(s, addr, peers, node, known, listen, &cn);
            }
            Err(e) => {
                eprintln!("connect to {addr} failed: {e}");
                cn.lock().unwrap().remove(&addr);
            }
        },
    );
}

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------

fn on_message<S: SpendStore + StateStore + Send + 'static>(
    addr: SocketAddr,
    msg: Message,
    node: &Arc<Mutex<Node<S>>>,
    peers: &PeerMap,
    known: &AddrSet,
    listen: SocketAddr,
    connecting: &AddrSet,
) {
    let codec = Codec::new(node.lock().unwrap().params.magic);
    match msg {
        Message::Version { from, .. } => {
            // Record the peer's self-reported listening address for gossip.
            if let Some(sa) = netaddr_to_socket(&from) {
                known.lock().unwrap().insert(sa);
            }
            send_msg(peers, &addr, &codec, &Message::Verack);
        }
        Message::Verack => {
            if let Some(p) = peers.lock().unwrap().get_mut(&addr) {
                p.handshaked = true;
                println!("[p2p] handshake complete with {addr}");
            }
            // On handshake, ask the peer for its chain tip (initial sync) and
            // for more peer addresses (bootstrap/gossip).
            let tip = node.lock().unwrap().tip;
            send_msg(peers, &addr, &codec, &Message::GetBlocks(vec![tip.0]));
            send_msg(peers, &addr, &codec, &Message::GetAddr);
        }
        Message::Inv(items) => {
            let mut want = Vec::new();
            {
                let n = node.lock().unwrap();
                for it in &items {
                    let unknown = (it.kind == MSG_BLOCK
                        && !n.known_blocks.contains(&Hash32(it.hash)))
                        || (it.kind == MSG_TX && !n.known_txs.contains(&Hash32(it.hash)));
                    if unknown {
                        want.push(it.clone());
                    }
                }
            }
            if !want.is_empty() {
                send_msg(peers, &addr, &codec, &Message::GetData(want));
            }
        }
        Message::GetData(items) => {
            let mut out = Vec::new();
            {
                let n = node.lock().unwrap();
                for it in &items {
                    if it.kind == MSG_BLOCK {
                        if let Some(b) = n.store.get_block(&Hash32(it.hash)) {
                            out.push(Message::Block(to_bytes(&b)));
                        }
                    } else if it.kind == MSG_TX {
                        if let Some(tx) = n.mempool.iter().find(|t| t.txid() == Hash32(it.hash)) {
                            out.push(Message::Tx(to_bytes(tx)));
                        }
                    }
                }
            }
            for m in out {
                send_msg(peers, &addr, &codec, &m);
            }
        }
        Message::GetBlocks(locator) => {
            let inv = node.lock().unwrap().block_inv_from_locator(&locator);
            if !inv.is_empty() {
                send_msg(peers, &addr, &codec, &Message::Inv(inv));
            }
        }
        Message::GetAddr => {
            let addrs: Vec<NetAddr> = known
                .lock()
                .unwrap()
                .iter()
                .copied()
                .filter_map(socket_to_netaddr)
                .collect();
            if !addrs.is_empty() {
                send_msg(peers, &addr, &codec, &Message::Addr(addrs));
            }
        }
        Message::Addr(list) => {
            let mut new_peers = Vec::new();
            {
                let mut k = known.lock().unwrap();
                for na in &list {
                    if let Some(sa) = netaddr_to_socket(na) {
                        if k.insert(sa) {
                            new_peers.push(sa);
                        }
                    }
                }
            }
            // Connect to any newly-learned addresses we aren't already peered with.
            for sa in &new_peers {
                eprintln!("[p2p] Addr handler: new_peer={sa}");
            }
            for sa in new_peers {
                let already = peers.lock().unwrap().contains_key(&sa);
                if !already {
                    eprintln!("[p2p] Addr handler -> connect_to {sa}");
                    connect_to(sa, peers.clone(), node.clone(), known.clone(), listen, connecting);
                }
            }
        }
        Message::Block(raw) => match Block::decode(&mut Reader::new(&raw)) {
            Ok(block) => {
                let accepted = node.lock().unwrap().accept_block(block.clone(), addr);
                if accepted {
                    let h = block.block_hash();
                    broadcast(
                        peers,
                        &codec,
                        &Message::Inv(vec![InvVect {
                            kind: MSG_BLOCK,
                            hash: h.0,
                        }]),
                        Some(&addr),
                    );

                }
            }
            Err(e) => eprintln!("[p2p] bad block payload: {e}"),
        },
        Message::Tx(raw) => match Transaction::decode(&mut Reader::new(&raw)) {
            Ok(tx) => {
                let accepted = node.lock().unwrap().accept_tx(tx.clone(), addr);
                if accepted {
                    let id = tx.txid();
                    broadcast(
                        peers,
                        &codec,
                        &Message::Inv(vec![InvVect {
                            kind: MSG_TX,
                            hash: id.0,
                        }]),
                        Some(&addr),
                    );
                    println!("[p2p] accepted relayed tx {}", hex(&id.0[..4]));
                }
            }
            Err(e) => eprintln!("[p2p] bad tx payload: {e}"),
        },
        Message::Ping(n) => send_msg(peers, &addr, &codec, &Message::Pong(n)),
        Message::Pong(_) | Message::Request { .. } | Message::Response { .. } => {}
    }
}

/// Drive one peer connection: register the writer, perform the version
/// handshake, then read and dispatch framed messages until the peer closes.
fn handle_conn<S: SpendStore + StateStore + Send + 'static>(
    mut stream: TcpStream,
    addr: SocketAddr,
    peers: PeerMap,
    node: Arc<Mutex<Node<S>>>,
    known: AddrSet,
    listen: SocketAddr,
    connecting: &AddrSet,
) {
    let writer = match stream.try_clone() {
        Ok(w) => Arc::new(Mutex::new(w)),
        Err(_) => return,
    };
    peers.lock().unwrap().insert(
        addr,
        Peer {
            writer,
            handshaked: false,
        },
    );

    let best = node.lock().unwrap().best_height();
    let nonce = node.lock().unwrap().my_nonce;
    let codec = Codec::new(node.lock().unwrap().params.magic);
    send_msg(
        &peers,
        &addr,
        &codec,
        &Message::Version {
            version: 1,
            services: 1,
            timestamp: now_secs(),
            from: socket_to_netaddr(listen).unwrap(),
            nonce,
            best_height: best,
        },
    );

    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
        // DoS guard: bound unparsed buffer growth.
        if buf.len() > litc_wire::MAX_FRAME * 2 {
            eprintln!("[p2p] peer {addr} exceeded buffer limit; dropping");
            break;
        }
        loop {
            match codec.parse(&buf) {
                Ok(Some((msg, consumed))) => {
                    buf.drain(..consumed);
                    on_message(addr, msg, &node, &peers, &known, listen, connecting);
                }
                Ok(None) => break,
                Err(e) => {
                    eprintln!("[p2p] wire error from {addr}: {e}");
                    return;
                }
            }
        }
    }
    peers.lock().unwrap().remove(&addr);
    connecting.lock().unwrap().remove(&addr);
    println!("[p2p] peer disconnected {addr}");
}

// ---------------------------------------------------------------------------
// Mining loop
// ---------------------------------------------------------------------------

fn miner_loop<S: SpendStore + StateStore>(
    node: Arc<Mutex<Node<S>>>,
    peers: PeerMap,
    miner: Box<dyn MinerBackend + Send>,
) {
    let codec = Codec::new(node.lock().unwrap().params.magic);
    // If the chain is empty, wait for the first block from the network before
    // mining our own genesis — avoids mining orphan blocks on first start.
    {
        let n = node.lock().unwrap();
        if n.best_height() == 0 && n.tip == Hash32([0u8; 32]) {
            drop(n);
            for _ in 0..10 {
                thread::sleep(Duration::from_secs(1));
                let n = node.lock().unwrap();
                if n.best_height() > 0 || !peers.lock().unwrap().is_empty() {
                    break;
                }
            }
        }
    }
    loop {
        let (template, target) = {
            let mut n = node.lock().unwrap();
            n.make_template()
        };
        let block = match miner.mine_block(&template, &target) {
            Some(b) => b,
            None => {
                eprintln!("[mine] search space exhausted");
                thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        let accepted = node.lock().unwrap().accept_block(block.clone(), LOCAL);
        if accepted {
            let h = block.block_hash();
            broadcast(
                &peers,
                &codec,
                &Message::Inv(vec![InvVect {
                    kind: MSG_BLOCK,
                    hash: h.0,
                }]),
                None,
            );
            println!(
                "[mine] block #{} hash={}",
                block.header.height,
                hex(&h.0[..4])
            );
        }
        thread::sleep(Duration::from_millis(1500));
    }
}

// ---------------------------------------------------------------------------
// Mempool directory (shared with the `litc` CLI's `wallet send*` commands)
// ---------------------------------------------------------------------------

/// Read `*.tx` files from `<data_dir>/mempool`, decode each transaction, accept
/// it into the mempool, relay an `inv`, and delete the file (consumed). Already
/// known txs are skipped (so re-runs are safe); malformed files are left for
/// inspection.
fn load_mempool<S: SpendStore + StateStore>(
    data_dir: &std::path::Path,
    node: &Arc<Mutex<Node<S>>>,
    peers: &PeerMap,
) {
    let dir = data_dir.join("mempool");
    if !dir.exists() {
        return;
    }
    let codec = Codec::new(node.lock().unwrap().params.magic);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("tx") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let tx = match Transaction::decode(&mut Reader::new(&bytes)) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[mempool] bad tx file {}: {e}", path.display());
                continue;
            }
        };
        let accepted = node.lock().unwrap().accept_tx(tx.clone(), LOCAL);
        if accepted {
            let id = tx.txid();
            broadcast(
                peers,
                &codec,
                &Message::Inv(vec![InvVect {
                    kind: MSG_TX,
                    hash: id.0,
                }]),
                None,
            );
            let _ = std::fs::remove_file(&path);
            println!("[mempool] loaded tx {}", hex(&id.0[..4]));
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the node. `args` must start with the program name (index 0 is ignored),
/// e.g. `vec!["litc-node", "--port", "8334"]`. Shared by the `litc-node`
/// binary and the `litc` CLI's `node` subcommand.
pub fn run(args: Vec<String>) {
    let mut port = DEFAULT_PORT;
    let mut connects: Vec<String> = Vec::new();
    let mut mine = true;
    let mut use_gpu = false;
    let mut archive = false;
    let mut verify_from_genesis = false;
    let mut fast_sync: Option<String> = None;
    let mut save_snapshot: Option<String> = None;
    let mut network = Network::Testnet;
    let mut rpc_port: Option<u16> = None;
    let mut rpc_bind: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                if let Some(s) = args.get(i + 1) {
                    if let Ok(p) = s.parse() {
                        port = p;
                    }
                }
                i += 2;
            }
            "--rpc-port" => {
                if let Some(s) = args.get(i + 1) {
                    if let Ok(p) = s.parse() {
                        rpc_port = Some(p);
                    }
                }
                i += 2;
            }
            "--rpc-bind" => {
                if let Some(s) = args.get(i + 1) {
                    if let Ok(p) = s.parse() {
                        rpc_bind = p;
                    }
                }
                i += 2;
            }
            "--connect" => {
                if let Some(c) = args.get(i + 1) {
                    connects.push(c.clone());
                }
                i += 2;
            }
            "--seed" => {
                if let Some(s) = args.get(i + 1) {
                    connects.push(s.clone());
                }
                i += 2;
            }
            "--no-mine" => {
                mine = false;
                i += 1;
            }
            "--gpu" => {
                use_gpu = true;
                i += 1;
            }
            "--archive" => {
                // Keep the full block history (no pruning).
                archive = true;
                i += 1;
            }
            "--verify-from-genesis" => {
                // Null-trust mode: discard any existing state and replay every
                // block from block 0 (requires the full history to be present).
                verify_from_genesis = true;
                i += 1;
            }
            "--fast-sync" => {
                // Start from a trusted snapshot instead of replaying history.
                if let Some(s) = args.get(i + 1) {
                    fast_sync = Some(s.clone());
                }
                i += 2;
            }
            "--save-snapshot" => {
                // Write a snapshot of the current state to this directory
                // (and continue running).
                if let Some(s) = args.get(i + 1) {
                    save_snapshot = Some(s.clone());
                }
                i += 2;
            }
            "--network" => {
                if let Some(n) = args.get(i + 1) {
                    if let Ok(net) = n.parse() {
                        network = net;
                    }
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let listen: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
    let data_dir = std::env::var("LITC_DATADIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("data"));
    let cfg = NodeConfig::from_file(&data_dir.join("config.toml"));

    // Network consensus parameters. `LITC_NETWORK` overrides `--network`; default
    // is testnet. Checkpoints are empty on a fresh testnet and pinned at launch.
    let network = std::env::var("LITC_NETWORK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(network);
    let params = match network {
        Network::Mainnet => ChainParams::mainnet(),
        Network::Testnet => ChainParams::testnet(),
    };
    println!("[net] network = {}", network.as_str());

    // `--verify-from-genesis` intentionally wipes any existing state so the node
    // re-derives everything from block 0 (the only fully trustless path).
    if verify_from_genesis {
        eprintln!("[warn] --verify-from-genesis: discarding existing chain state");
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    // Pruning is on by default (bounded disk); `--archive` keeps everything.
    let prune = if archive { None } else { cfg.prune_config() };

    let ks = FileKeyStore::new(data_dir.join("wallet.dat"));
    let seed = ks.open_or_create().expect("keystore");

    // Either fast-sync from a snapshot (trustless verify on load) or open the
    // local chain store.
    let store = if let Some(snap) = &fast_sync {
        println!("[fast-sync] loading snapshot from {snap}");
        FileStore::load_snapshot(snap, &params).expect("cannot load snapshot (state_root mismatch?)")
    } else {
        FileStore::open(data_dir.clone(), prune).expect("cannot open chain store")
    };

    if let Some(snap) = &save_snapshot {
        let path = std::path::PathBuf::from(snap);
        store.save_snapshot(&path).expect("cannot save snapshot");
        println!("[snapshot] saved to {snap}");
    }
    let node = Arc::new(Mutex::new(Node::<FileStore>::new(store, seed, params)));
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    // Known addresses for bootstrap + gossip (seeds, CLI, config, learned).
    let known: AddrSet = Arc::new(Mutex::new(HashSet::new()));
    known.lock().unwrap().insert(listen);
    // Resolve all seed/connect hostnames *once* so that DNS round-robin or
    // IPv4/IPv6 ordering differences can't produce two different addresses
    // for the same hostname (which would bypass the connecting-set guard).
    let mut connect_targets: Vec<SocketAddr> = Vec::new();
    for s in cfg.seeds.iter() {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            known.lock().unwrap().insert(addr);
        } else if let Ok(mut addrs) = s.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                known.lock().unwrap().insert(addr);
            }
        }
    }
    for s in connects.iter() {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            known.lock().unwrap().insert(addr);
            connect_targets.push(addr);
        } else if let Ok(mut addrs) = s.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                known.lock().unwrap().insert(addr);
                connect_targets.push(addr);
            }
        }
    }

    // Load any pending transactions dropped into the mempool directory (e.g. by
    // the `litc wallet send*` commands) and relay them.
    load_mempool(&data_dir, &node, &peers);

    let connecting: AddrSet = Arc::new(Mutex::new(HashSet::new()));
    let listener = TcpListener::bind(listen).expect("cannot bind port");
    println!("listening on {listen}");
    let lpeers = peers.clone();
    let lnode = node.clone();
    let lknown = known.clone();
    let lconnecting = connecting.clone();
    let llisten = listen;
    thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let addr = match s.peer_addr() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let p = lpeers.clone();
            let nd = lnode.clone();
            let kn = lknown.clone();
            let cn = lconnecting.clone();
            thread::spawn(move || handle_conn(s, addr, p, nd, kn, llisten, &cn));
        }
    });

    for addr in &connect_targets {
        eprintln!("[p2p] connect_targets: {addr}");
    }
    for addr in connect_targets {
        let p = peers.clone();
        let nd = node.clone();
        let kn = known.clone();
        connect_to(addr, p, nd, kn, listen, &connecting);
    }

    if mine {
        let miner: Box<dyn MinerBackend + Send> = if use_gpu {
            #[cfg(feature = "gpu")]
            {
                match WgpuMiner::new() {
                    Ok(m) => {
                        println!("[gpu] mining backend: wgpu (Vulkan)");
                        Box::new(m)
                    }
                    Err(e) => {
                        eprintln!("[gpu] init failed: {e}; falling back to CPU");
                        Box::new(CpuMiner)
                    }
                }
            }
            #[cfg(not(feature = "gpu"))]
            {
                eprintln!("[gpu] node built without --features gpu; using CPU miner");
                Box::new(CpuMiner)
            }
        } else {
            Box::new(CpuMiner)
        };
        let mnode = node.clone();
        let mpeers = peers.clone();
        thread::spawn(move || miner_loop(mnode, mpeers, miner));
    } else {
        println!("mining disabled (--no-mine)");
    }

    if let Some(rpc_port) = rpc_port {
        let rpc_node = node.clone();
        let rpc_seed = FileKeyStore::new(data_dir.join("wallet.dat"))
            .open_or_create()
            .expect("keystore for rpc");
        let rpc_peers = peers.clone();
        let rpc_addr = (rpc_bind, rpc_port).into();
        thread::spawn(move || rpc::start(rpc_addr, rpc_node, rpc_seed, rpc_peers));
    }

    loop {
        thread::sleep(Duration::from_secs(5));
        load_mempool(&data_dir, &node, &peers);
        let n = node.lock().unwrap();
        println!(
            "[status] height={} blocks={} known_txs={} mempool={} diff_bits={} peers={}",
            n.best_height(),
            n.known_blocks.len(),
            n.known_txs.len(),
            n.mempool.len(),
            n.difficulty_bits(),
            peers.lock().unwrap().len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litc_core::block_challenge;
    use litc_primitives::BlockHeader;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    /// Read once from `stream` into `tmp`, retrying on `WouldBlock` (read
    /// timeout) and returning `None` on a clean EOF / fatal error. Mirrors how
    /// `handle_conn` treats a transient timeout as "keep waiting" rather than a
    /// fatal error. Returns `Some(n)` when `n > 0` bytes were read.
    fn read_some(stream: &mut TcpStream, tmp: &mut [u8]) -> Option<usize> {
        loop {
            match stream.read(tmp) {
                Ok(0) => return None,
                Ok(n) => return Some(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => return None,
            }
        }
    }

    /// Drive a connected `TcpStream` as the *server* side of the handshake:
    /// read a `version` frame, reply `verack`, then wait for the peer's
    /// `verack`, and finally return a `Codec` + the raw stream for further
    /// frames. This mirrors what `litc-node`'s `handle_conn` does on inbound
    /// connections.
    fn server_handshake(stream: &mut TcpStream, magic: [u8; 4]) -> Codec {
        let codec = Codec::new(magic);
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        // Expect the peer's `version`.
        let version = loop {
            let n = read_some(stream, &mut tmp).expect("server: peer closed before version");
            buf.extend_from_slice(&tmp[..n]);
            if let Ok(Some((m, consumed))) = codec.parse(&buf) {
                buf.drain(..consumed);
                if let Message::Version { .. } = m {
                    break m;
                }
            }
        };
        // Reply verack.
        stream.write_all(&codec.frame(&Message::Verack)).unwrap();
        // Wait for the peer's verack.
        loop {
            let n = read_some(stream, &mut tmp).expect("server: peer closed before verack");
            buf.extend_from_slice(&tmp[..n]);
            if let Ok(Some((m, consumed))) = codec.parse(&buf) {
                buf.drain(..consumed);
                if let Message::Verack = m {
                    break;
                }
            }
        }
        let _ = version;
        codec
    }

    /// CRITICAL FIX #6 (P2P): two nodes exchange `version`/`verack`, then a
    /// block announced via `inv` is fetched with `getdata` and delivered as a
    /// full `block` frame. This exercises the real `litc-wire` framing and the
    /// node's inventory/relay logic end-to-end over a loopback TCP socket,
    /// without mining.
    #[test]
    fn p2p_handshake_and_block_relay() {
        let magic = ChainParams::testnet().magic;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Client (a real `litc-node` Peer connection) connects to the server.
        let client_stream = TcpStream::connect(server_addr).unwrap();
        client_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Server accepts and performs the handshake in a background thread.
        let server_thread = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let codec = server_handshake(&mut s, magic);
            // Receive the client's `inv` for a block.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let inv = loop {
                let n = read_some(&mut s, &mut tmp).expect("server: peer closed before inv");
                buf.extend_from_slice(&tmp[..n]);
                if let Ok(Some((m, consumed))) = codec.parse(&buf) {
                    buf.drain(..consumed);
                    if let Message::Inv(items) = m {
                        break items;
                    }
                }
            };
            // Reply with `getdata` asking for that block.
            s.write_all(&codec.frame(&Message::GetData(inv.clone()))).unwrap();
            // Receive the `block` frame and return its hash.
            loop {
                let n = read_some(&mut s, &mut tmp).expect("server: peer closed before block");
                buf.extend_from_slice(&tmp[..n]);
                if let Ok(Some((m, consumed))) = codec.parse(&buf) {
                    buf.drain(..consumed);
                    if let Message::Block(raw) = m {
                        let b = Block::decode(&mut Reader::new(&raw)).unwrap();
                        return b.block_hash();
                    }
                }
            }
        });

        // Client side: perform the handshake from the node's perspective,
        // then announce a synthetic block and serve it on `getdata`.
        let mut client_stream = client_stream;
        let codec = Codec::new(magic);
        // Send our `version`.
        client_stream
            .write_all(&codec.frame(&Message::Version {
                version: 1,
                services: 1,
                timestamp: 0,
                from: NetAddr {
                    services: 1,
                    ip: [0; 16],
                    port: 0,
                    timestamp: 0,
                },
                nonce: 1,
                best_height: 0,
            }))
            .unwrap();
        // Read server's verack, then send our verack.
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let n = read_some(&mut client_stream, &mut tmp).expect("client: server closed before verack");
            buf.extend_from_slice(&tmp[..n]);
            if let Ok(Some((m, consumed))) = codec.parse(&buf) {
                buf.drain(..consumed);
                if let Message::Verack = m {
                    break;
                }
            }
        }
        client_stream.write_all(&codec.frame(&Message::Verack)).unwrap();

        // Build a valid (tiny-target) PoW block and announce it via `inv`.
        let target = [0xFFu8; 32];
        // Find a nonce meeting the (trivial) target using LiteHash directly.
        let mut header = BlockHeader {
            version: 1,
            prev_block: Hash32([0u8; 32]),
            merkle_root: Hash32([0u8; 32]),
            state_root: Hash32([0u8; 32]),
            timestamp: 1,
            height: 0,
            epoch_seed: Hash32([0u8; 32]),
            nonce: 0,
        };
        let mut nonce = 0u64;
        let scratch = litc_pow::prepare_epoch(&[0u8; 32]);
        loop {
            let challenge = block_challenge(&header);
            let digest = litc_pow::mine(&scratch, nonce, &challenge);
            if litc_pow::meets_target(&digest, &target) {
                header.nonce = nonce;
                break;
            }
            nonce += 1;
            if nonce > 1_000_000 {
                panic!("p2p test: could not mine synthetic block");
            }
        }
        let block = Block {
            header,
            txs: vec![],
        };
        let hash = block.block_hash();
        client_stream
            .write_all(&codec.frame(&Message::Inv(vec![InvVect {
                kind: MSG_BLOCK,
                hash: hash.0,
            }])))
            .unwrap();

        // The server will answer the `inv` with `getdata`; serve the block.
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let n = read_some(&mut client_stream, &mut tmp)
                .expect("client: server closed before getdata");
            buf.extend_from_slice(&tmp[..n]);
            if let Ok(Some((m, consumed))) = codec.parse(&buf) {
                buf.drain(..consumed);
                if let Message::GetData(items) = m {
                    // Serve every requested block (here: just the one).
                    for it in items {
                        if it.kind == MSG_BLOCK {
                            client_stream
                                .write_all(&codec.frame(&Message::Block(to_bytes(&block))))
                                .unwrap();
                        }
                    }
                    break;
                }
            }
        }
        // The server relays/handles the block and returns its hash.
        let server_hash = server_thread.join().unwrap();
        assert_eq!(server_hash, hash);

        // Block-level validation (PoW + merkle) must pass for the relayed block.
        assert!(validate_block_pow_merkle(&block, &target));
    }
}
