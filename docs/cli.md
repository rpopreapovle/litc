# LiTC command-line client (`litc`)

Two binaries ship from this repo:

- **`litc-node`** — the P2P / mining node (see `docs/specification.md`).
- **`litc`** — a thin client wrapping the node and the wallet.

State lives under `$LITC_DATADIR` (default `./data`):

| File                | Contents                                              |
|--------------------|-------------------------------------------------------|
| `wallet.dat`       | 32-byte master seed (the only secret)                 |
| `wallet.dat.stealth` | recovered one-time stealth spend keys (persisted) |
| `chain.dat`        | append-only block records (header + optional body)    |
| `chain.idx`        | per-height `(offset,len,has_body)` index for `seek`   |
| `utxo.dat`         | the live UTXO set (flat, rewritten on every change)   |
| `burnt.dat`        | spent output commitments (20-byte keys)               |
| `tip.dat`          | current best-block hash                               |
| `mempool/*.tx`     | signed transactions dropped in for the node to mine   |
| `config.toml`      | optional node configuration (see below)               |

## `litc node`

Runs the node. All `litc-node` flags apply (the `litc` wrapper forwards
them). Examples straight from the original docs:

```bash
# Mine and relay on the default port.
litc node --port 8333
# A second node that only relays.
litc node --port 8334 --connect 127.0.0.1:8333 --no-mine
# Optional GPU mining backend (build with --features gpu).
litc node --gpu
# Bootstrap from an explicit seed (same as --connect, advertised for gossip).
litc node --seed 1.2.3.4:8333
# Bind a specific listen address (used for self-advertisement in P2P gossip).
litc node --listen 0.0.0.0:8333 --seed seed.example.com:8333
```

Node flags:

| flag          | meaning                                                          |
|---------------|------------------------------------------------------------------|
| `--port N`    | listen port (default 8333)                                       |
| `--listen IP:PORT` | address to bind **and** advertise to peers (default `127.0.0.1:N`) |
| `--connect A` | dial a peer at `A` on startup (also added to the gossip set)      |
| `--seed A`    | alias for `--connect` (semantically a bootstrap seed)             |
| `--no-mine`   | relay + sync only, do not mine                                   |
| `--gpu`       | use the GPU mining backend (build with `--features gpu`)          |

The node persists its chain under `$LITC_DATADIR` and periodically drains
`$LITC_DATADIR/mempool/*.tx` (written by `wallet send*`), relaying
and mining them.

### `config.toml` — the `[node]` section

Optionally create `$LITC_DATADIR/config.toml` to tune pruning for a weak
VPS. The only recognized section is `[node]`:

```toml
[node]
# Enable block pruning: drop old block bodies, keep only headers + the
# live UTXO set. On by default; set `prune = false` to keep every body.
prune = true

# Target size of the retained block history, in megabytes. The node keeps
# roughly this many bytes of block bodies and prunes everything older.
# Default 512 MB (~2880 blocks at ~15 s/block ≈ 12 h of history).
prune_target_size_mb = 512

# Alternatively pin the retained depth directly (number of recent blocks to
# keep with full bodies). If set, it overrides prune_target_size_mb.
# prune_keep_depth = 2880

# Bootstrap seed nodes (comma-separated "host:port"). Each is dialed on
# startup and advertised to peers via addr gossip.
seeds = "seed1.litc.example:8333, seed2.litc.example:8333"
```

Pruning is applied continuously: whenever the chain advances past
`keep_depth`, earlier blocks are rewritten as header-only in `chain.dat`
and compacted in `chain.idx`, so disk usage stays bounded. The coinbase
and the live `utxo.dat` set are never pruned, so wallet balances and
spending keep working against a pruned node.

## `litc wallet`

```bash
litc wallet new              # create the wallet; print legacy + stealth address
litc wallet address [i]   # print the legacy WOTS+ address at index i (0)
litc wallet stealth         # print the reusable stealth address
litc wallet balance       # confirmed balance (legacy + stealth)
litc wallet scan           # list owned stealth outputs found by scanning
litc wallet send <to> <amount> [--from i]            # pay a legacy address
litc wallet send-stealth <to> <amount> [--from i]  # pay a stealth address
```

`<amount>` is either whole satoshis or `<n>.<frac>LIT`
(`litc wallet send-stealth <addr> 10.5` = 10.5 LIT). `send`/`send-stealth`
build a signed transaction, write it to `mempool/<txid>.tx`, and print
its hex; a running `litc node` picks it up and mines it.

## Example session

```bash
export LITC_DATADIR=/tmp/litc-demo
litc wallet new                 # addresses are derived from a fresh seed
litc node --port 8333 &     # starts mining to this wallet's address
sleep 9
litc wallet balance           # shows the mined coinbase (50 LIT/block)
litc wallet send-stealth "$(litc wallet stealth)" 10.0   # pay self
sleep 9
litc wallet scan              # the stealth output is found + spendable
```
