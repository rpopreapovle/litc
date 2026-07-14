# LiTC Local RPC (binary, same format as P2P)

Before any TCP P2P, the node exposes its functionality over a **local binary
RPC**. This is the first "network" layer and exists so the node, wallet, miner,
and tests can talk immediately — no custom text format, no JSON.

It reuses the single `litc-wire` codec (see [protocol.md](protocol.md)). The
exact same `Message` frames used here are later used on the P2P wire. One
format, everywhere.

## Transport

- Default: **Unix socket** `~/.litc/node.sock`.
- Optional: TCP `127.0.0.1` (port from `[node] rpc_bind`).
- Frames: `[magic:4][cmd:1][len:4][payload]` — identical to P2P.

## Client

`litc-cli` is the client:

```bash
litc node &
litc cli get_info
litc cli wallet_new
litc cli wallet_send <to> <amount>
```

No `curl`, no JSON — the wire is binary.

## Requests / responses

Local RPC adds two wire messages on top of the P2P set:

| cmd | Name     | payload              | purpose |
|-----|----------|----------------------|---------|
| 11  | request  | id, method, params  | RPC call |
| 12  | response | id, ok, data        | RPC result |

Methods (binary-encoded params):

- `get_info` → network, best height, best hash.
- `get_block {hash|height}` → header + txids.
- `get_height` → best height.
- `send_tx {raw_tx}` → txid once **accepted into mempool** (`pending`).
- `get_tx {txid}` → tx with status `pending` / `confirmed` / `high`.
- `wallet_new` → new address (via KeyStore).
- `wallet_balance {addr}` → confirmed + pending.
- `wallet_send {to, amount}` → build, sign (KeyStore), submit.
- `mine_once` → mine one block from mempool + coinbase.
- `set_mining {enabled, backend}` → `cpu` (always) or `gpu` (feature).

## Why this comes before TCP

Writing P2P first would delay every test. With the local binary RPC the whole
stack (chain, wallet, miner) is exercisable on day one, using the same codec
P2P will use — so the integration test needs no sockets and no second format.
