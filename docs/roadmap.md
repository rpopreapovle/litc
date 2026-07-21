# LiTC Roadmap

Staged so every step is testable and adds something the user can feel.
Guided by [PHILOSOPHY.md](PHILOSOPHY.md): no step is taken that does not
simplify LiTC or improve it for the ordinary user.

## Stage 1 — Wire codec
`litc-wire`: ONE binary codec — `Message` enum, `Serialize`/`Deserialize`,
`Codec` (framing `[magic][cmd][len][payload]`). Used by node RPC and P2P
alike. No second serializer, no JSON.

## Stage 2 — Primitives
`litc-primitives`: SHA-256d, merkle, WOTS+ keys/sign, block & tx types.
Unit tests for each.

**KEM wrapper (stealth addresses):** add a `kem` module on top of ML-KEM-512
(RustCrypto `ml-kem`, FIPS 203 — post-quantum). Expose a small, dependency-light
wrapper: `kem_keypair_from_seed(seed) -> (pk, sk)`, `kem_encaps(pk) ->
(shared, ct)`, `kem_decaps(sk, ct) -> shared`. The KEM is used only to build
reusable stealth addresses; it never signs. The decapsulation key is a 64-byte
seed derived deterministically from the wallet master seed, so the wallet
stays stateless (one master seed). See [stealth.md](stealth.md).

## Stage 3 — Storage traits
`litc-store`: `BlockStore`, `ChainStore`, `UtxoStore` traits + `Memory*`
(tests) and `File*` (MVP).

## Stage 4 — Core consensus
`litc-core`: validation, UTXO apply, mempool, difficulty retarget (±25%,
every 30 blocks), reorg, confirmation model (pending / 1 / 6).

## Stage 5 — Keys and wallet
`litc-keystore` (`FileKeyStore`) + `litc-wallet` (balance, build/sign tx).
Wallet holds no secrets.

**Reusable stealth addresses:** `litc-wallet` derives an ML-KEM-512
encapsulation key from the master seed and exposes `stealth_address()`.
`send_stealth(recipient, value)` builds an output that locks a fresh one-time
WOTS+ key and carries the KEM ciphertext in `TxOut.ephemeral`. `scan_chain()`
walks every UTXO, decapsulates each `ephemeral` with the scan key, and recovers
the WOTS+ spend key for outputs whose commitment matches — then persists those
keys to the `KeyStore` (the `StealthKey` records) so owned outputs survive
restarts. `spend_stealth()` signs a spend with the recovered key. A "for
dummies" wallet just sees its balance rise; the address never changes. See
[stealth.md](stealth.md).

## Stage 6 — CPU miner
`litc-miner`: `MinerBackend` trait + `CpuMiner`. Node mines abstractly.

## Stage 7 — Node + local binary RPC
`litc-node` (wires core+store+miner+wire; listens on Unix socket / TCP
127.0.0.1) and `litc-cli` (client). First network layer; fast tests, one
format.

## Stage 8 — Integration test (automatic)
`cargo test` spins two in-process cores (MemoryStore): tx → mine → reorg →
assert OK. No sockets needed.

## Stage 9 — Benchmarks
`docs/benchmarks.md`: measure on Xeon E5, Celeron, GTX 650, RX 580,
RTX 3060. Lock LiteHash `N` (512 MB), `W` (walk length) and
`EPOCH_BLOCKS` so commodity hardware stays competitive. Confirm CPU and
GPU land close; pick on measured fairness, not habit.

## Stage 10 — P2P (binary, minimal, decentralized) — **DONE**
Delivered in `litc-node` (TCP, reusing `litc-wire`) rather than a separate
`litc-p2p` crate: `version, verack, inv, getdata, tx, block, ping, pong,
getaddr, addr` plus the local RPC frames. Handshake, inventory relay, rate
limits, and address gossip with no hardcoded seeds. **Compact-block relay**
(short tx IDs, BIP152-style) is the planned fast path; full `block` is the
current fallback. No JSON.

## Stage 11 — GPU miner (optional)
`litc-miner-gpu-wgpu` behind `gpu` feature. Verified on RTX 3060 (Vulkan).

## Stage 12 — Docs + reproducible builds
Complete `docs/`; `cargo build --locked` yields deterministic releases.

Delivered binaries and libraries live in `docs/cli.md` (the `litc` client and
`litc-node` daemon) and `docs/ffi.md` (the `litc-ffi` C-ABI library usable from
any FFI-capable language). The reusable stealth-address scheme is documented in
`docs/stealth.md`; the WOTS+ reuse strategy in `docs/wots.md`.

## Definition of Done (MVP testnet)
- `cargo build --locked` works without GPU deps; `--features gpu` adds wgpu GPU miner.
- `cargo test` runs the 2-node tx/mine/reorg scenario automatically.
- Transfers confirm in <20 s, fees low, config TOML, PHILOSOPHY exists, spec
  open and justified, one binary format everywhere.
- LiteHash parameters are benchmark-backed.

## Session 2026-07-15 — consensus hardening (all DONE)

The following were added on top of the MVP and are documented in
[specification.md](specification.md), [state.md](state.md), and [wots.md](wots.md).

### Stage 13 — Consensus state commitment (state_root + SMT)
Block header carries `state_root = SHA-256d(utxo_root || burnt_root)`, where
both roots are Sparse Merkle Trees. A bootstrapping node verifies the root by
applying each block over a read-only overlay and recomputing it, so the PoW
secures the resulting state, not just transitions. See [state.md](state.md).

### Stage 14 — Signature-scheme agility (SignatureScheme)
Every `TxIn` declares `scheme: SignatureScheme` (`Wots256` active at launch;
`Reserved1..3` recognized-but-inactive; `Unknown` rejected). `validate_tx`
dispatches per scheme; the scheme byte is part of the sighash, binding each
signature to its scheme. Reserved ids leave room for future post-quantum /
hybrid schemes without a flag-day fork.

### Stage 15 — Snapshot + fast-sync
`FileStore::save_snapshot` / `load_snapshot` let a node bootstrap from a
trusted state snapshot (UTXO + burnt + tip block) instead of replaying from
genesis. Loading is trustless: the stored `state_root` is recomputed and a
mismatch (tampering) is rejected. Versioned format (`magic "LITS"`, `version`)
with a tamper-detection test. Node CLI: `--archive`, `--verify-from-genesis`,
`--fast-sync <dir>`, `--save-snapshot <dir>`.

### Stage 16 — Network parameters, genesis pinning, checkpoints
`litc-primitives::chainparams`: `Network{Mainnet,Testnet}` + `ChainParams`
(`magic`, `halving_interval`, `genesis_hash`, `checkpoints`). The node picks
the network via `--network` / `LITC_NETWORK`. A block at a checkpoint height
must carry the pinned hash (`validate_checkpoint`), which finalizes history
at/below it and **bounds fast-sync trust** — a snapshot is only accepted if its
tip matches the highest checkpoint at or below its height. The genesis hash is
pinned as a checkpoint at testnet launch.

### Next (not yet done)
- **Stage 17 — Fast-sync end-to-end test**: mine a chain, snapshot, start a
  fresh node from the snapshot, confirm it catches up. (unit test exists;
  node-level e2e pending)
- **Stage 18 — P2P smoke / 2-node sync test** and **compact-block relay**.
  - `p2p_handshake_and_block_relay` unit test now covers handshake + `inv`/
    `getdata`/block relay over loopback TCP (DONE).
- **Stage 19 — Throughput benchmark** for WOTS+ `w=256` (already active) and
  tx/s under block validation. WOTS+ witness/throughput numbers added to
  `docs/benchmarks.md` (DONE).
