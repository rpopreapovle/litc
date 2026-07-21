# LiTC JSON-RPC API

The node exposes an HTTP JSON-RPC 2.0 API for wallet operations, chain
queries, mining control, and light wallet integration.

## Enable

```
cargo run -p litc-node -- --port 8333 --rpc-port 18334
```

By default RPC binds `127.0.0.1` (localhost only). For remote light wallet
access, bind to a routable address:

```
cargo run -p litc-node -- --port 8333 --rpc-port 18334 --rpc-bind 0.0.0.0
```

No auth is enforced — use a firewall or SSH tunnel for remote access.

## Usage

```bash
curl -s http://127.0.0.1:18334/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"<method>","params":[...],"id":1}'
```

## Methods

### Blockchain

| Method | Params | Returns |
|---|---|---|
| `getblockcount` | `[]` | Current chain height |
| `getbestblockhash` | `[]` | Hex of the current tip hash |
| `getblockhash` | `[height]` | Block hash at `height` |
| `getblock` | `[hash, verbose?]` | Block data (verbose=1: JSON, 0: hex) |

### Wallet

| Method | Params | Returns |
|---|---|---|
| `getstealthaddress` | `[]` | The wallet's reusable stealth address |
| `getbalance` | `[]` | Stealth balance (satoshis and formatted) |
| `listunspent` | `[min_amount?]` | Array of UTXOs with txid, vout, amount |
| `sendtostealthaddress` | `[to, amount, from_index?]` | Build, sign, and submit tx to stealth address |
| `gettransaction` | `[txid]` | Transaction info (mempool + chain) |

`amount` is either raw satoshis or `<n>.<frac>LIT` (e.g. `"10.5"` = 10.5 LIT).

### Light wallet

| Method | Params | Returns |
|---|---|---|
| `get_utxos` | `[["<commit_hex>", ...]]` | UTXOs for given commitments |
| `get_tx` | `[txid]` | Raw hex transaction + confirmations |
| `broadcast_raw_tx` | `[hex]` | `txid` if accepted |
| `get_header_by_height` | `[height]` | Hex-encoded block header |
| `get_network_params` | `[]` | Chain parameters (subsidy, halving, etc.) |

### Mining

| Method | Params | Returns |
|---|---|---|
| `getmininginfo` | `[]` | Height, difficulty bits, mempool count |
| `submitblock` | `[hex]` | `true` if block was accepted |

### Network

| Method | Params | Returns |
|---|---|---|
| `getpeerinfo` | `[]` | Array of connected peers with address |
| `getconnectioncount` | `[]` | Number of connected peers |

### General

| Method | Params | Returns |
|---|---|---|
| `getinfo` | `[]` | Version, network, height, tip, difficulty, peers, mempool |

## Errors

| Code | Meaning |
|---|---|
| `-32601` | Method not found |
| `-32700` | Parse error |
| `-5` | Invalid address, txid, or block hash |
| `-25` | Transaction or block rejected |
| `-32602` | Invalid parameters |
