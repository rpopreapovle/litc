# Running a LiTC Node (testnet MVP)

## Prerequisites

- Rust stable (edition 2021+).
- Linux (LiTC is Linux-first; portable elsewhere best-effort).
- For GPU mining only: OpenCL runtime.

## Build

```bash
git clone <repo> && cd litc
cargo build --locked              # CPU-only node + wallet + miner
cargo build --locked --features gpu   # also the OpenCL miner crate
```

`--locked` uses the committed `Cargo.lock` → reproducible (see
[reproducible-builds.md](reproducible-builds.md)).

## Configure

```bash
cp config.toml.example config.toml
```

```toml
[network]
testnet = true
magic   = 0x4C315443   # "L1TC"
port    = 19333

[p2p]
enabled  = false       # turn on after the P2P stage
max_peers = 8

[node]
socket   = "~/.litc/node.sock"   # local RPC (binary, litc-wire)
rpc_bind = "127.0.0.1:9332"    # optional TCP RPC

[miner]
backend = "cpu"        # "gpu" only with --features gpu
threads = 0            # 0 = auto

[wallet]
keystore = "file"
path     = "~/.litc/wallet.dat"
```

## Run

```bash
litc node                        # runs the node + CPU miner, serves local RPC
litc node --miner-backend gpu   # with --features gpu build
litc cli wallet_new             # create address (via KeyStore)
litc cli wallet_balance <addr>
litc cli wallet_send <to> <amount>
litc mine                        # optional separate miner connecting to the node
```

## What you get

- A block roughly every **15 seconds**.
- A tx is `pending` in mempool immediately, `confirmed` after 1 block (fine
  for everyday pay), `high` after 6.
- Low, size-based fees.
- GPU acceleration is optional; CPU mining is a first-class citizen.

## Next (later stages)

When `[p2p] enabled = true`, the node connects to peers over the binary
protocol in [protocol.md](protocol.md).
