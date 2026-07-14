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

## Stage 10 — P2P (binary, minimal, decentralized)
`litc-p2p`: TCP reusing `litc-wire` — `version, verack, inv, getdata, tx,
block, ping, pong, getaddr, addr`. `getaddr`/`addr` give peer discovery with no
hardcoded seeds. **Compact-block relay** (short tx IDs, BIP152-style) is required
so 750 KB blocks propagate fast at 15 s cadence. No JSON.

## Stage 11 — GPU miner (optional)
`litc-miner-gpu-opencl` behind `gpu` feature. Verified on GTX 650.

## Stage 12 — Docs + reproducible builds
Complete `docs/`; `cargo build --locked` yields deterministic releases.

Delivered binaries and libraries live in `docs/cli.md` (the `litc` client and
`litc-node` daemon) and `docs/ffi.md` (the `litc-ffi` C-ABI library usable from
any FFI-capable language). The reusable stealth-address scheme is documented in
`docs/stealth.md`; the WOTS+ reuse strategy in `docs/wots.md`.

## Definition of Done (MVP testnet)
- `cargo build --locked` works without OpenCL; `--features gpu` adds GPU miner.
- `cargo test` runs the 2-node tx/mine/reorg scenario automatically.
- Transfers confirm in <20 s, fees low, config TOML, PHILOSOPHY exists, spec
  open and justified, one binary format everywhere.
- LiteHash parameters are benchmark-backed.
