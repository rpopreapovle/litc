# Running a LiTC Node

## Prerequisites

- Rust stable (edition 2021+).
- Linux (LiTC is Linux-first; portable elsewhere best-effort).
- For GPU mining only: Vulkan driver (NVIDIA, AMD, or Intel).

## Build

```bash
git clone https://github.com/litc-project/litc && cd litc
cargo build --locked                   # CPU node, wallet, CLI
cargo build --locked --features gpu    # also build the wgpu GPU miner
```

The default build uses a small PoW scratchpad (`litc-pow/small`, 4096 lanes ×
1024 walk steps) so mining is instant without a 512 MB working set. Drop the
`small` feature for the real memory-hard parameter.

## Run

```bash
# Mining node (default port 8333).
cargo run -p litc-node --features litc-pow/small -- --port 8333

# Relay-only node (syncs, does not mine).
cargo run -p litc-node --features litc-pow/small -- --port 8334 \
    --connect 127.0.0.1:8333 --no-mine

# With GPU mining backend.
cargo run -p litc-node --features gpu,litc-pow/small -- --port 8333 --gpu

# With JSON-RPC API on port 18334.
cargo run -p litc-node --features litc-pow/small -- --port 8333 --rpc-port 18334
```

## Command-line flags

| Flag | Default | Description |
|---|---|---|
| `--port N` | `8333` | TCP listen port (P2P) |
| `--rpc-port N` | (none) | Enable JSON-RPC on this port |
| `--connect A` | — | Dial peer `A` on startup |
| `--seed A` | — | Same as `--connect` (bootstrap seed) |
| `--no-mine` | mining on | Disable CPU/GPU mining |
| `--gpu` | CPU | Use wgpu GPU backend (requires `--features gpu`) |
| `--archive` | prune on | Keep full block history (no pruning) |
| `--verify-from-genesis` | — | Wipe state and replay from block 0 |
| `--fast-sync <path>` | — | Load chain snapshot from `path` |
| `--save-snapshot <path>` | — | Write state snapshot to `path` |
| `--network <name>` | `testnet` | `testnet` or `mainnet` |

P2P binds `0.0.0.0:PORT`. RPC binds `127.0.0.1:RPC-PORT` (localhost only).

## Environment

| Variable | Default | Description |
|---|---|---|
| `LITC_DATADIR` | `./data` | Data directory (chain, wallet, mempool) |
| `LITC_NETWORK` | `--network` value | Override `--network` |

## State files

Under `$LITC_DATADIR`:

| File | Contents |
|---|---|
| `wallet.dat` | 32-byte master seed |
| `chain.dat` | Append-only block records |
| `chain.idx` | Block index for seeking |
| `utxo.dat` | Live UTXO set |
| `tip.dat` | Current best-block hash |
| `mempool/*.tx` | Pending signed transactions |

## Wallet

```bash
# Create wallet and print ML-DSA-2 address.
cargo run -p litc-cli -- wallet new

# Check balance.
cargo run -p litc-cli -- wallet balance

# Show receiving address.
cargo run -p litc-cli -- wallet address

# Send coins.
cargo run -p litc-cli -- wallet send <address> <amount>
```

Or use the JSON-RPC API (see [rpc.md](rpc.md)).
