# LiTC Wallet

The wallet is deliberately split from secret storage
(see [specification.md](specification.md)).

- `litc-wallet` — balance, building and signing transactions. Holds **no
  secrets**.
- `litc-keystore` — the `KeyStore` trait. Today: `FileKeyStore`
  (`wallet.dat`). Later: `Ledger`, `Trezor` — without touching the wallet.

## Keys and addresses

- Scheme: **ML-DSA-2** (Dilithium, NIST FIPS 204). Stateless, reusable
  post-quantum signatures. See `litc-primitives::mldsa`.
- Address: `bech32m("litc", version || HASH160(ml_dsa_pk))` → ~40 characters.
  - Mainnet: HRP `litc`, version `0x31` → `litc1q…`
  - Testnet: HRP `tlitc`, version `0x70` → `tlitc1q…`
- The wallet derives a **keypair from the master seed** deterministically.
  One address per seed+index. ML-DSA-2 keys are reusable — no one-time
  limitation, no stealth scanning, no burnt keys.
- At spend time, the full public key (1312 bytes) is revealed in the
  witness. The UTXO script commits to `HASH160(pk)` (20 bytes).

## Commands

```bash
litc wallet new                 # new keypair in KeyStore, prints address
litc wallet balance <address>   # confirmed + pending
litc wallet send <to> <amount>  # build + sign (KeyStore) + submit via RPC
```

## Backup

For `FileKeyStore`, back up `wallet.dat` (or the exported private key).
Because secrets live only in the KeyStore, switching to a hardware
wallet later needs no wallet rewrite — just point `wallet.keystore` at the new
backend.

## Confirmation model

The wallet reports levels, not a single hardcoded number:

- `pending` — in mempool, not yet mined.
- `confirmed` — 1 block; enough for everyday payments.
- `high` — 6 blocks; for large sums.

See [specification.md](specification.md#blocks-and-transactions).
