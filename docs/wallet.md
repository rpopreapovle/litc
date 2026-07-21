# LiTC Wallet

The wallet is deliberately split from secret storage
(see [specification.md](specification.md)).

- `litc-wallet` — balance, building and signing transactions. Holds **no
  secrets**.
- `litc-keystore` — the `KeyStore` trait. Today: `FileKeyStore`
  (`wallet.dat`). Later: `Ledger`, `Trezor` — without touching the wallet.

## Keys and addresses

- Scheme: **WOTS+** (hash-based, post-quantum, one-time). See [wots.md](wots.md).
- Address: `base58check(version || HASH160(R))`, where `R` is the WOTS+ public
  root committed by the key.
  - Mainnet version `0x30` → `L…`
  - Testnet version `0x6F` → `m…`
- The wallet derives a **fresh address per payment** from the master seed, so
  addresses are never reused (one-time signatures + built-in privacy).
- For a **stable, reusable address**, the wallet also derives an ML-KEM-512
  encapsulation key from the master seed and exposes it as a stealth address
  (Bech32m, HRP `litc`/`tlitc` on mainnet/testnet, version byte in the data).
  Give this single address out; every payment you receive lands on a unique
  one-time
  WOTS+ output that only your wallet can recognize and spend. See
  [stealth.md](stealth.md).

## Commands

```bash
litc wallet new                 # new keypair in KeyStore, prints address
litc wallet stealth             # print reusable stealth address
litc wallet balance <address>  # confirmed + pending (works for both kinds)
litc wallet send <to> <amount> # build + sign (KeyStore) + submit via RPC
litc wallet send-stealth <to> <amount>  # pay a reusable stealth address
```


## Backup

For `FileKeyStore`, back up `wallet.dat` (or the exported private key). Recovered
stealth spend keys are persisted alongside it in `wallet.dat.stealth`, so back
up both — without the `.stealth` file you can still *see* your balance (the
scan key is in `wallet.dat`) but cannot *spend* previously received stealth
outputs. Because secrets live only in the KeyStore, switching to a hardware
wallet later needs no wallet rewrite — just point `wallet.keystore` at the new
backend.

## Confirmation model

The wallet reports levels, not a single hardcoded number:

- `pending` — in mempool, not yet mined.
- `confirmed` — 1 block; enough for everyday payments.
- `high` — 6 blocks; for large sums.

See [specification.md](specification.md#blocks-and-transactions).
