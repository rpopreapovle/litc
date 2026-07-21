# LiTC command-line client (`litc`)

Two binaries ship from this repo:

- **`litc-node`** — the P2P / mining / RPC node.
- **`litc`** — a thin CLI client wrapping the wallet and node.

State lives under `$LITC_DATADIR` (default `./data`):

| File                | Contents                                              |
|---------------------|-------------------------------------------------------|
| `wallet.dat`        | 32-byte master seed (the only secret)                 |
| `chain.dat`         | append-only block records (header + optional body)    |
| `chain.idx`         | per-height index for seeking                          |
| `utxo.dat`          | the live UTXO set (flat, rewritten on every change)   |
| `tip.dat`           | current best-block hash                               |
| `mempool/*.tx`      | signed transactions waiting to be mined               |

## `litc node`

Runs the node. Forwards all flags to `litc-node`.

```bash
# Mine and relay on the default port.
litc node --port 8333
# Relay-only node.
litc node --port 8334 --connect 127.0.0.1:8333 --no-mine
# With GPU mining backend (build with --features gpu).
litc node --gpu
# With JSON-RPC API.
litc node --port 8333 --rpc-port 18334
# Bootstrap from an explicit seed.
litc node --seed 1.2.3.4:8333
# Note: P2P binds 0.0.0.0:PORT; RPC always on 127.0.0.1.
```

Node flags:

| flag                  | meaning                                                    |
|-----------------------|------------------------------------------------------------|
| `--port N`            | listen port (default 8333)                                 |
| `--rpc-port N`        | enable JSON-RPC API on this port                           |
| `--connect A`         | dial peer `A` on startup (added to gossip set)             |
| `--seed A`            | alias for `--connect`                                      |
| `--no-mine`           | relay + sync only, do not mine                             |
| `--gpu`               | use GPU mining backend (requires `--features gpu`)         |
| `--archive`           | keep full block history (no pruning)                       |
| `--verify-from-genesis` | replay chain from genesis                                 |
| `--fast-sync <path>`  | load chain snapshot from file                              |
| `--save-snapshot <path>` | write state snapshot to file                             |
| `--network <name>`    | `testnet` or `mainnet` (default `testnet`)                  |

The node persists chain under `$LITC_DATADIR` and drains `mempool/*.tx`
(written by `wallet send`), relaying and mining them.

## `litc wallet`

```bash
litc wallet new                # create wallet; print the ML-DSA-2 address
litc wallet balance            # confirmed balance
litc wallet send <to> <amount> # pay a LiTC address
```

`<amount>` is whole satoshis or `<n>.<frac>LIT` (e.g. `10.5` = 10.5 LIT).
`send` writes a signed tx to `mempool/<txid>.tx` and prints the hex;
a running `litc node` picks it up.

## Example session

```bash
export LITC_DATADIR=/tmp/litc-demo
litc wallet new                 # fresh seed, litc1q... address printed
litc node --port 8333 &         # starts mining to this wallet's address
sleep 9
litc wallet balance             # shows mined coinbase (5 LIT/block)
litc wallet send "$(litc wallet address)" 10.0   # pay self
```
