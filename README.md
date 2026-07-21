# LiTC — Lightweight Transaction Coin

**LiTC** is a lightweight, post-quantum, CPU-friendly Proof-of-Work coin.
Light code, light protocol, light launch, light mining, light spec.

## What does "LiTC" stand for?

LiTC is a recursive, three-way acronym:

- **L**ightweight **T**ransaction **C**oin.
- **L**ightweight **T**rustless **C**ash.
- **L**atency-bound **I**nternet **T**oken (a nod to our latency-bound PoW).

- **CPU + old GPUs welcome.** Our own latency-bound Proof-of-Work
  ([LiteHash](docs/pow.md)) gives no ASIC advantage; CPU mining is a
  first-class citizen.
- **~15-second blocks.** One confirmation is enough for everyday payments.
- **Post-quantum by design.** Signatures are [WOTS+](docs/wots.md) and
  addresses are [ML-KEM-512 stealth](docs/stealth.md) — post-quantum safe.
- **Small, readable Rust.** Minimal deps, compact binary protocol,
  [open specification](docs/specification.md).

> Status: **public testnet MVP.** Protocol, consensus, wallet, P2P sync,
> mining, and RPC are implemented.

## Highlights

| Area            | What's there                                                        |
|-----------------|---------------------------------------------------------------------|
| Consensus       | PoW + cumulative-work chain selection, reorgs, undo log             |
| Signatures      | WOTS+ (one-time, PQ-safe), one-time-reuse guard                     |
| Addresses       | Reusable post-quantum stealth addresses (ML-KEM-512)                |
| PoW             | LiteHash — memory-hard, TMTO-resistant, latency-bound               |
| Networking      | Minimal binary P2P: version handshake, addr gossip, block sync      |
| Storage         | Append-only block store with pruning (weak-node friendly)           |
| Mining          | CPU backend + optional wgpu GPU backend                             |
| RPC API         | HTTP JSON-RPC 2.0: wallet, chain queries, mining control            |
| Interfaces      | `litc-node` binary, `litc` CLI client, C FFI (`litc-ffi`)          |

## Build

```bash
git clone https://github.com/litc-project/litc && cd litc
cargo build --locked                 # CPU node + wallet + miner + CLI
cargo build --locked --features gpu  # also build the wgpu GPU miner
```

The default build uses a small PoW scratchpad (`litc-pow/small`) for fast
test mining. Drop the `small` feature for the real memory-hard parameter.

## Quick start

```bash
# 1. Run a mining node with RPC.
cargo run -p litc-node --features litc-pow/small -- --port 8333 --rpc-port 18334

# 2. In another terminal, create a wallet and check balance.
cargo run -p litc-cli -- wallet new
cargo run -p litc-cli -- wallet balance

# 3. Use the JSON-RPC API.
curl -s http://127.0.0.1:18334/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}'

# 4. Relay-only second node.
cargo run -p litc-node --features litc-pow/small -- --port 8334 \
    --connect 127.0.0.1:8333 --no-mine
```

State lives under `$LITC_DATADIR` (default `./data`). See
[running-a-node.md](docs/running-a-node.md), [cli.md](docs/cli.md), and
[rpc.md](docs/rpc.md) for full references.

## Repository layout

```
crates/
  litc-wire           Binary wire protocol + framing
  litc-pow            LiteHash Proof-of-Work
  litc-primitives     Transactions, blocks, WOTS+, ML-KEM stealth
  litc-store          Append-only block store + UTXO set, pruning
  litc-core           Validation, chain selection, reorgs
  litc-wallet         Keystore-backed wallet
  litc-keystore       File-backed secret store
  litc-miner          CPU miner + BlockTemplate
  litc-miner-gpu-wgpu Optional wgpu GPU mining backend
  litc-node           P2P node + RPC API + miner driver
  litc-cli            Command-line client
  litc-ffi            C API for embeddings / bindings
docs/                 Protocol, PoW, WOTS+, stealth, CLI, RPC, roadmap
```

## Documentation

All docs live in [`docs/`](docs/):

- [PHILOSOPHY.md](docs/PHILOSOPHY.md) — principles and the "one rule".
- [specification.md](docs/specification.md) — protocol parameters, with reasons.
- [roadmap.md](docs/roadmap.md) — staged plan.
- [protocol.md](docs/protocol.md) — minimal binary P2P wire format.
- [pow.md](docs/pow.md) — LiteHash design.
- [rpc.md](docs/rpc.md) — HTTP JSON-RPC API reference.
- [wots.md](docs/wots.md) — WOTS+ signatures.
- [stealth.md](docs/stealth.md) — post-quantum stealth addresses.
- [mining.md](docs/mining.md) — algorithm and commodity hardware.
- [wallet.md](docs/wallet.md) — keys, backup, transfers.
- [cli.md](docs/cli.md) — node + CLI reference.
- [running-a-node.md](docs/running-a-node.md) — build and run.
- [reproducible-builds.md](docs/reproducible-builds.md) — deterministic releases.
- [benchmarks.md](docs/benchmarks.md) — hardware numbers.

## Security

LiTC is experimental cryptography software. See [SECURITY.md](SECURITY.md)
for supported versions and how to report vulnerabilities, and
[CONTRIBUTING.md](CONTRIBUTING.md) to get involved.

## License

Licensed under the [MIT License](LICENSE). Contributions welcome under
the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
