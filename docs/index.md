# LiTC — Lightweight Transaction Coin

LiTC is a lightweight Proof-of-Work cryptocurrency for ordinary users.

- **Light code** — small, readable Rust codebase.
- **Light protocol** — minimal binary protocol, no JSON on the wire.
- **Light launch** — one binary, `cargo build --locked`.
- **Light mining** — CPU + old GPUs welcome; latency-bound algo, no ASIC.
- **Light spec** — a compact, open, documented protocol.

## At a glance

| Property            | LiTC                                    |
|---------------------|-----------------------------------------|
| Consensus           | Proof of Work (LiteHash, 512 MB, latency-bound) |
| Block time          | ~15 seconds                             |
| Confirmations       | 1 block = everyday pay; 6 = high value |
| Mining              | CPU + optional wgpu GPU backend          |
| Cryptography        | ML-DSA-2 (Dilithium, FIPS 204, PQ, reusable) |
| Supply cap          | 84,000,000 LIT                          |
| Codebase            | Rust, workspace of small crates         |
| Platform            | Linux-first, portable                   |
| RPC API             | HTTP JSON-RPC 2.0                       |

## Why a new coin?

Most users want: a simple wallet, fast transfers, low fees, a reliable network.
LiTC is built so that the *default experience* is light — the node is smaller,
confirmations are faster, and mining stays on hardware people already own.

See [PHILOSOPHY.md](PHILOSOPHY.md) for the guiding principles, and
[specification.md](specification.md) for exact parameters and their reasons.

## Repository layout

```
litc/
  Cargo.toml            # workspace; feature "gpu" enables wgpu miner
  docs/                 # this documentation (English)
  crates/
    litc-wire           # binary codec: Message, Serialize/Deserialize
    litc-primitives     # hash, merkle, ML-DSA-2 keys/sign, block, tx
    litc-store          # append-only block store + UTXO set
    litc-core           # validation, utxo, mempool, difficulty, reorg
    litc-keystore       # file-backed secret store
    litc-wallet         # wallet logic (no secrets)
    litc-miner          # CPU miner + BlockTemplate
    litc-miner-gpu-wgpu # optional wgpu GPU mining backend
    litc-node           # P2P node + RPC + miner driver
    litc-cli            # command-line client
    litc-ffi            # C API for embeddings / bindings
```

## Documentation

- [PHILOSOPHY.md](PHILOSOPHY.md) — principles and the "one rule".
- [specification.md](specification.md) — protocol parameters, with rationale.
- [roadmap.md](roadmap.md) — implementation stages.
- [rpc.md](rpc.md) — HTTP JSON-RPC API reference.
- [protocol.md](protocol.md) — binary P2P wire format.
- [mining.md](mining.md) — algorithm and commodity hardware.
- [pow.md](pow.md) — LiteHash design.
- [wots.md](wots.md) — WOTS+ signatures (**historical**, removed).
- [stealth.md](stealth.md) — stealth address protocol (**historical**, removed).
- [ml-dsa-migration.md](ml-dsa-migration.md) — ML-DSA-2 migration plan.
- [benchmarks.md](benchmarks.md) — hardware measurements.
- [running-a-node.md](running-a-node.md) — build, configure, run.
- [wallet.md](wallet.md) — keys, backup, transfers.
- [uri.md](uri.md) — payment URIs, QR codes, deep links.
- [cli.md](cli.md) — node + CLI reference.
- [reproducible-builds.md](reproducible-builds.md) — deterministic releases.
