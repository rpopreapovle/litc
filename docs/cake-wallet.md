# Cake Wallet + LiTC integration

## Architecture

```
┌──────────────────────┐      RPC (TLS optional)      ┌─────────────────┐
│  Mobile App          │ ◄──────────────────────────►  │  Backend Node   │
│  (Flutter / Kotlin)  │                               │  (server)       │
│                      │  getblockcount                │                 │
│  ┌────────────────┐  │  get_utxos(commitments[])     │  litc-node      │
│  │ litc-lightwallet│  │  get_tx(txid)                 │  (full chain)   │
│  │ (Rust → C FFI) │  │  broadcast_tx(hex)           │                 │
│  │                │  │  get_header_by_height(h)      │                 │
│  │ key derivation │  └─────────────────────────────► │                 │
│  │ tx building    │                                   │                 │
│  │ signing        │                                   │                 │
│  └────────────────┘                                   └─────────────────┘
```

**Mobile app** — runs the light wallet library, which holds keys, builds/signs
transactions. No blockchain data is stored.

**Backend node** — a full `litc-node` instance running on a server with a
public IP. Serves UTXO set, block headers, and transactions to light wallets.
Multiple light wallets share one backend node.

## Light wallet library (`litc-lightwallet`)

A Rust crate `crates/litc-lightwallet` that wraps key operations and server
communication. **Stateless** (like `litc-wallet`): no persistent storage, no
blockchain.

### Public API

```rust
pub struct LightWallet {
    seed: [u8; 32],
}

impl LightWallet {
    /// Create from a 32-byte master seed.
    pub fn new(seed: [u8; 32]) -> Self;

    // ── Address derivation ──

    /// ML-DSA-2 address at index `i` (bech32m, ~40 chars).
    pub fn address_at(&self, i: u32) -> String;

    /// The 20-byte commitment HASH160(pk) for index `i`.
    pub fn commitment_at(&self, i: u32) -> [u8; 20];

    // ── Balance (requires server) ──

    /// Fetch UTXOs for a set of commitments from the server.
    pub fn fetch_utxos(server_url: &str, commitments: &[[u8; 20]])
        -> Result<Vec<Utxo>, Error>;

    /// Compute total balance from fetched UTXOs.
    pub fn balance(&self, utxos: &[Utxo]) -> Amount;

    // ── Spending (local signing + server broadcast) ──

    /// Build and sign a transaction to an address.
    pub fn build_send(
        &self, utxos: &[Utxo], from_index: u32,
        to: &str, value: Amount,
    ) -> Result<String, Error>;  // returns hex

    /// Broadcast a signed hex tx to the server.
    pub fn broadcast(server_url: &str, hex_tx: &str)
        -> Result<String, Error>;  // returns txid
}
```

### FFI (C ABI for Flutter/Kotlin/Swift)

```c
// Create wallet from hex seed.
const char* lw_from_seed(const char* hex_seed);

// Derive ML-DSA-2 address.
const char* lw_address(const char* wallet_json, uint32_t index);

// Fetch UTXOs from server.
const char* lw_fetch_utxos(const char* server_url,
                           const char* commitments_json);

// Build & sign tx locally, return hex.
const char* lw_send(const char* wallet_json,
                    const char* utxos_json,
                    uint32_t from_index,
                    const char* to_address,
                    uint64_t value_satoshis);

// Broadcast hex tx to server.
const char* lw_broadcast(const char* server_url, const char* hex_tx);
```

## New RPC endpoints

### `get_utxos`

Returns UTXOs for a set of commitments (20-byte HASH160 hashes).

```
Params: [["<commit_hex>", ...]]
Result: [
  {
    "txid": "<hex>",
    "vout": 0,
    "value": 500000000,
    "commit": "<hex>",
    "height": 42
  },
  ...
]
```

### `get_tx`

Returns a raw hex transaction for a given txid.

```
Params: ["<txid_hex>"]
Result: {
  "hex": "<raw_tx_hex>",
  "confirmations": 12
}
```

### `broadcast_raw_tx`

Accepts a pre-signed raw transaction hex, validates it, adds to mempool, and
relays.

```
Params: ["<hex_tx>"]
Result: { "txid": "<hex>" }
```

### `get_header_by_height`

Returns the block header at a given height.

```
Params: [42]
Result: {
  "hex": "<raw_header_hex>",
  "hash": "<hex>"
}
```

### `get_network_params`

Returns chain parameters.

```
Params: []
Result: {
  "version": 1,
  "subsidy": 500000000,
  "halving_interval": 8400000,
  "coinbase_maturity": 100,
  "target_interval": 15,
  "decimals": 8
}
```

## Security

- **No private keys on the server.** Signing happens entirely on-device.
- **Future: TLS + API key** on the RPC port for production use.
