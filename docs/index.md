# LiTC — Lightweight Transaction Coin

LiTC is a lightweight Proof-of-Work cryptocurrency for ordinary users.

- **Light code** — small, readable Rust codebase.
- **Light protocol** — minimal binary protocol, no JSON on the wire.
- **Light launch** — one binary, TOML config, `cargo build --locked`.
- **Light mining** — CPU + old GPUs (GTX 650) welcome; our own latency-bound algo, no ASIC needed.
- **Light spec** — a compact, open, documented protocol.

## At a glance

| Property            | LiTC                                    |
|---------------------|-----------------------------------------|
| Consensus           | Proof of Work (LiteHash, 512 MB, latency-bound) |
| Block time          | ~15 seconds                             |
| Confirmations       | 1 block = everyday pay; 6 = high value |
| Mining              | CPU + GPU; our own latency-bound algo     |
| Cryptography        | WOTS+ (quantum-resistant, one-time), SHA-256, merkle tree |
| Supply cap          | 84,000,000 LIT                          |
| Codebase            | Rust, workspace of small crates         |
| Platform            | Linux-first, portable                   |

## Why a new coin?

Most users want: a simple wallet, fast transfers, low fees, a reliable network.
LiTC is built so that the *default experience* is light — the node is smaller,
confirmations are faster, and mining stays on hardware people already own.

See [PHILOSOPHY.md](PHILOSOPHY.md) for the guiding principles, and
[specification.md](specification.md) for exact parameters and their reasons.

## Repository layout

```
litc/
  Cargo.toml            # workspace; feature "gpu" enables OpenCL miner
  config.toml.example
  docs/                 # this documentation (English)
  crates/
    litc-wire/          # ONE binary codec: Message, Serialize/Deserialize, Codec
    litc-primitives/    # hash, merkle, WOTS+ keys/sign, block, tx
    litc-store/         # traits BlockStore / ChainStore / UtxoStore (+ Memory/File)
    litc-core/          # validation, utxo, mempool, difficulty, reorg, confirmations
    litc-keystore/      # trait KeyStore: FileKeyStore (Ledger/Trezor later)
    litc-wallet/        # wallet logic (no secrets); uses KeyStore + stores
    litc-miner/         # trait MinerBackend; CpuMiner
    litc-miner-gpu-wgpu/  # OPTIONAL, feature "gpu"
    litc-node/          # node: wires core+store+miner+wire; local socket + (later) P2P
    litc-cli/           # client: talks to node over litc-wire (binary) via socket/TCP
    litc/               # binary: `litc node | wallet | mine | cli`
```

## Documentation

- [PHILOSOPHY.md](PHILOSOPHY.md) — principles and the "one rule".
- [specification.md](specification.md) — protocol parameters, with rationale.
- [roadmap.md](roadmap.md) — implementation stages.
- [rpc.md](rpc.md) — localhost RPC (first networking layer).
- [protocol.md](protocol.md) — binary P2P wire format (added later).
- [mining.md](mining.md) — algorithm, parameters, running on commodity hardware.
- [pow.md](pow.md) — LiTC Proof-of-Work (LiteHash) design.
- [wots.md](wots.md) — LiTC signatures: WOTS+ (quantum-resistant, one-time).
- [benchmarks.md](benchmarks.md) — hardware measurements that fix the PoW params (LiteHash).
- [running-a-node.md](running-a-node.md) — build, configure, run.
- [wallet.md](wallet.md) — keys, backup, transfers.
- [reproducible-builds.md](reproducible-builds.md) — deterministic releases.
