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
│  │ stealth scan   │                                   │                 │
│  └────────────────┘                                   └─────────────────┘
```

**Mobile app** — runs the light wallet library, which holds keys, builds/signs
transactions, and scans for stealth payments. No blockchain data is stored.

**Backend node** — a full `litc-node` instance running on a server with a
public IP. Serves UTXO set, block headers, and transactions to light wallets.
Multiple light wallets share one backend node.

## Light wallet library (`litc-lightwallet`)

A new Rust crate `crates/litc-lightwallet` that wraps key operations and server
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

    /// Legacy WOTS+ address at index `i` (base58check).
    pub fn address_at(&self, i: u32) -> String;

    /// Reusable stealth address (Bech32m).
    pub fn stealth_address(&self) -> String;

    // ── Balance (requires server) ──

    /// Fetch UTXOs for a set of commitments from the server.
    pub fn fetch_utxos(server_url: &str, commitments: &[[u8; 20]])
        -> Result<Vec<Utxo>, Error>;

    /// Compute total balance from fetched UTXOs.
    pub fn balance(&self, utxos: &[Utxo]) -> Amount;

    // ── Spending (local signing + server broadcast) ──

    /// Build and sign a transaction to a legacy address.
    pub fn send_to_address(
        &self, utxos: &[Utxo], from_index: u32,
        to: &str, value: Amount,
    ) -> Result<String, Error>;  // returns hex

    /// Build and sign a stealth payment.
    pub fn send_to_stealth(
        &self, utxos: &[Utxo], from_index: u32,
        recipient: &str, value: Amount,
    ) -> Result<String, Error>;

    /// Broadcast a signed hex tx to the server.
    pub fn broadcast(server_url: &str, hex_tx: &str)
        -> Result<String, Error>;  // returns txid

    // ── Stealth scanning (requires server) ──

    /// Scan server UTXOs for stealth payments to this wallet.
    /// Returns list of (outpoint, value, spend_key_index) found.
    pub fn scan_stealth(server_url: &str, kem_sk: &[u8; KEM_SK_LEN])
        -> Result<Vec<OwnedStealth>, Error>;
}
```

### FFI (C ABI for Flutter/Kotlin/Swift)

The library exports a C API via `litc-ffi` (or its own FFI module):

```c
// All functions return a JSON string for portability.

// Create wallet from hex seed.
const char* lw_from_seed(const char* hex_seed);

// Derive addresses.
const char* lw_address(const char* wallet_json, uint32_t index);
const char* lw_stealth_address(const char* wallet_json);

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

// Scan stealth outputs.
const char* lw_scan_stealth(const char* server_url,
                            const char* wallet_json);
```

Flutter calls these via `dart:ffi` or a method channel. No platform-specific
code needed — the C library compiles for Android (arm64) and iOS (aarch64).

## New RPC endpoints

The backend node needs three new read-only endpoints so a light wallet does
not need to own a wallet on the server:

### `get_utxos`

Returns UTXOs for a set of WOTS+ commitments (20-byte HASH160 hashes).

```
Params: [["<commit_hex>", ...]]
Result: [
  {
    "txid": "<hex>",
    "vout": 0,
    "value": 500000000,
    "commit": "<hex>",
    "height": 42,           // block height (for coinbase maturity check)
    "ephemeral": "<hex>"    // KEM ciphertext if stealth, else ""
  },
  ...
]
```

### `get_tx`

Returns a raw hex transaction for a given txid (searches store + mempool).

```
Params: ["<txid_hex>"]
Result: {
  "hex": "<raw_tx_hex>",
  "confirmations": 12
}
```

### `broadcast_raw_tx`

Accepts a pre-signed raw transaction hex (already built/signed on the mobile
device), validates it, adds to mempool, and relays.

```
Params: ["<hex_tx>"]
Result: { "txid": "<hex>" }
```

### `get_header_by_height`

Returns the block header at a given height (for SPV-style header chain
verification).

```
Params: [42]
Result: {
  "hex": "<raw_header_hex>",
  "hash": "<hex>"
}
```

### `get_network_params`

Returns chain parameters the light wallet needs to configure itself.

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

## Cake Wallet integration steps

1. Build `litc-lightwallet` as a C static library for Android + iOS
   (`cargo build --target aarch64-linux-android`, etc.).

2. Write a Flutter plugin (`litc_flutter/`) that wraps the C FFI calls in
   Dart.

3. Add LiTC as a coin in Cake Wallet's asset list:
   - Register the Flutter plugin.
   - Add coin params (name "LiTC", ticker "LIT", scheme "litecoin" — to reuse
     Cake's existing UTXO coin UI).
   - Point to a user-configurable backend node URL.

4. Provide a public list of backend nodes, or let users run their own
   `litc-node --rpc-port 18334 --rpc-bind 0.0.0.0`.

## Security

- **No private keys on the server.** Signing happens entirely on-device.
  The server only sees public commitments and signed transactions.
- **Stealth privacy preserved.** The server learns which commitments the
  wallet owns (scans all UTXOs). This is the same privacy model as Electrum
  or MyMonero — acceptable for most users.
- **Future: TLS + API key** on the RPC port for production use.

## Mobile-friendly parameters

For mobile use, the PoW scratchpad is fixed at 512 MB (too large for a phone).
The light wallet never mines or validates PoW — it trusts the server for
UTXO data and validates only the block header chain (SPV-style) using
`get_header_by_height` and merkle proofs from `get_tx`.

A future improvement: use the `state_root` from block headers to verify UTXO
inclusion proofs without downloading full blocks (see [state.md](state.md)).
