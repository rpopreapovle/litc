# LiTC JSON-RPC API

The node exposes an HTTP JSON-RPC 2.0 API on `127.0.0.1:<rpc-port>` for wallet
operations, chain queries, and mining control.

## Enable

```
cargo run -p litc-node -- --port 8333 --rpc-port 18334
```

The RPC server runs on a separate thread and shares the node state via
`Arc<Mutex<...>>`. No auth is enforced (localhost only).

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
| `getblock` | `[hash, 0]` | Raw hex-encoded block |

### Wallet

| Method | Params | Returns |
|---|---|---|
| `getnewaddress` | `[]` | A new unused legacy address |
| `getstealthaddress` | `[]` | The wallet's reusable stealth address |
| `getbalance` | `[]` | Legacy + stealth balances (satoshis and formatted) |
| `listunspent` | `[min_amount?]` | Array of UTXOs with txid, vout, amount |
| `sendtoaddress` | `[to, amount, from_index?]` | Build, sign, and submit tx to legacy address |
| `sendtostealthaddress` | `[to, amount, from_index?]` | Build, sign, and submit tx to stealth address |
| `gettransaction` | `[txid]` | Transaction info (mempool only currently) |

`amount` is either raw satoshis or `<n>.<frac>LIT` (e.g. `"10.5"` = 10.5 LIT).

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
| `getblockcount` | `[]` | Current chain height |

## Errors

Standard JSON-RPC 2.0 error codes:

| Code | Meaning |
|---|---|
| `-32601` | Method not found |
| `-32700` | Parse error |
| `-5` | Invalid address, txid, or block hash |
| `-25` | Block rejected |
