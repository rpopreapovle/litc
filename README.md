# LiTC — Lightweight Transaction Coin

**LiTC** is a lightweight, post-quantum, CPU-friendly Proof-of-Work coin.
Light code, light protocol, light launch, light mining, light spec.

## What does "LiTC" stand for?

LiTC is a recursive, three-way acronym — pick the reading you like best:

- **L**ightweight **T**ransaction **C**oin — *Легковесная Транзакционная Монета.*
- **L**ightweight **T**rustless **C**ash — *Легковесный Бездоверительный Кэш.*
- **L**atency-bound **I**nternet **T**oken — *Интернет-токен с ограничением по
  задержке* (a nod to our latency-bound Proof-of-Work, [LiteHash](docs/pow.md)).

> **Manifest.** Yes, we were inspired by Litecoin's original 2011 vision of
> light, everyday payments — but LiTC is built on entirely new technology, so
> LiTC is, first and foremost, a **Lightweight Transaction Coin**.

- **CPU + old GPUs welcome.** Our own latency-bound Proof-of-Work
  ([LiteHash](docs/pow.md)) gives no ASIC advantage; CPU mining is a
  first-class citizen.
- **~15-second blocks.** One confirmation is enough for everyday payments.
- **Post-quantum by design.** Signatures are [WOTS+](docs/wots.md) and
  addresses are [ML-KEM-512 stealth addresses](docs/stealth.md) — both
  resistant to quantum attackers.
- **Small, readable Rust.** Minimal dependencies, a compact binary protocol,
  and an [open specification](docs/specification.md).

> Status: **public testnet MVP.** The protocol, consensus, wallet, P2P sync,
> and mining are implemented and tested. Mainnet hardening, an external
> security audit, and fast-sync are planned (see [`todo`](todo) and
> [roadmap](docs/roadmap.md)).

## Highlights

| Area            | What's there                                                        |
|-----------------|---------------------------------------------------------------------|
| Consensus       | PoW + cumulative-work chain selection, reorganizations, undo log    |
| Signatures      | WOTS+ (one-time, quantum-resistant), one-time-reuse guard           |
| Addresses       | Reusable post-quantum stealth addresses (ML-KEM-512)                |
| PoW             | LiteHash — memory-hard, TMTO-resistant, latency-bound               |
| Networking      | Minimal binary P2P: version handshake, addr gossip, block sync      |
| Storage         | Append-only block store with continuous pruning (weak-node friendly)|
| Mining          | CPU backend + optional wgpu GPU backend                             |
| Interfaces      | `litc-node` binary, `litc` CLI client, and a C FFI (`litc-ffi`)     |

## Build

Requires Rust stable (edition 2021+).

```bash
git clone https://github.com/litc-project/litc && cd litc
cargo build --locked                 # CPU node + wallet + miner
cargo build --locked --features gpu  # also build the wgpu GPU miner
```

`--locked` uses the committed `Cargo.lock` for reproducible builds
(see [reproducible-builds.md](docs/reproducible-builds.md)).

> The default build uses a small PoW scratchpad (`litc-pow/small`) so the
> node mines quickly without a 512 MB working set. Drop the `small` feature
> for the real memory-hard parameter when you want production-like mining.

## Quick start

```bash
# 1. Run a mining node (writes state under ./data by default).
cargo run -p litc-node --features litc-pow/small -- --port 8333

# 2. In another terminal, a second node that only relays + syncs.
cargo run -p litc-node --features litc-pow/small -- --port 8334 \
    --connect 127.0.0.1:8333 --no-mine

# 3. Create a wallet and addresses via the CLI client.
cargo run -p litc-cli -- wallet_new            # legacy one-time address
cargo run -p litc-cli -- stealth_new           # reusable post-quantum address

# 4. Send coins.
cargo run -p litc-cli -- wallet_send <to-address> 1000000
```

State (wallet seed, chain, UTXOs) lives under `$LITC_DATADIR` (default
`./data`). See [running-a-node.md](docs/running-a-node.md) and
[cli.md](docs/cli.md) for the full command reference, `config.toml` options
(pruning, seeds), and RPC.

## Repository layout

```
crates/
  litc-wire        Binary wire protocol + framing (MAX_FRAME cap, codec)
  litc-pow         LiteHash Proof-of-Work (memory-hard scratchpad)
  litc-primitives  Transactions, blocks, WOTS+, ML-KEM stealth addresses
  litc-store       Append-only block store + UTXO/burnt sets, pruning
  litc-core        Validation, cumulative-work best chain, reorgs
  litc-wallet      Keystore-backed wallet: stealth send/scan/spend
  litc-miner       CPU miner + BlockTemplate
  litc-miner-gpu-wgpu  Optional wgpu GPU mining backend
  litc-keystore    File-backed secret store (master seed, used keys)
  litc-node        P2P node + miner driver (CLI entrypoint)
  litc-cli         Thin command-line client
  litc-ffi         C API for embeddings / bindings
docs/              Protocol, PoW, WOTS+, stealth, CLI, roadmap (English)
```

## Documentation

All protocol and design docs live in [`docs/`](docs/):

- [PHILOSOPHY.md](docs/PHILOSOPHY.md) — principles and the "one rule".
- [specification.md](docs/specification.md) — protocol parameters, with reasons.
- [roadmap.md](docs/roadmap.md) — staged plan.
- [protocol.md](docs/protocol.md) — minimal binary P2P wire format.
- [pow.md](docs/pow.md) — LiteHash design.
- [wots.md](docs/wots.md) — WOTS+ signatures.
- [stealth.md](docs/stealth.md) — post-quantum stealth addresses.
- [mining.md](docs/mining.md) — algorithm and commodity hardware.
- [wallet.md](docs/wallet.md) — keys, backup, transfers.
- [cli.md](docs/cli.md) — node + CLI reference.
- [running-a-node.md](docs/running-a-node.md) — build and run.
- [reproducible-builds.md](docs/reproducible-builds.md) — deterministic releases.
- [benchmarks.md](docs/benchmarks.md) — hardware numbers behind the PoW params.

## Security

LiTC is experimental cryptography software. See [SECURITY.md](SECURITY.md)
for supported versions and how to report vulnerabilities, and
[CONTRIBUTING.md](CONTRIBUTING.md) to get involved. A formal third-party
audit is planned before mainnet (see [roadmap](docs/roadmap.md)).

## License

Licensed under the [MIT License](LICENSE). Contributions are welcome under
the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
