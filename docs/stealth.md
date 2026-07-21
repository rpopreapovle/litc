# Stealth Addresses (Reusable, Post-Quantum)

LiTC gives every user a **single, stable address** to share — while every
payment on chain still goes to a unique one-time WOTS+ key. This hides the
one-time nature of WOTS+ behind the wallet, with no tree bloat (no XMSS/Falcon
statefulness).

The trick: a **post-quantum KEM** (ML-KEM-512, FIPS 203) lets the sender wrap a
fresh one-time signature key that only the recipient can unwrap.

## Why not a big signature tree?

- Falcon / XMSS give reusable keys but need **stateful trees** (or huge
  proofs). That bloats outputs and complicates the wallet.
- WOTS+ is stateless and compact but **one-time**.
- Stealth addressing keeps WOTS+ exactly as-is and adds a thin KEM layer for
  the *user experience* only. The chain still sees only one-time WOTS+ keys;
  the KEM ciphertext is an extra `ephemeral` blob carried **at the transaction
  level** (one capsule per transaction, not per output).

## Layout

```
Reusable address (what you share)   =  Bech32m(litc/tlitc || version || KEM_encaps_pk)
   HRP: "litc" mainnet, "tlitc" testnet; version byte 0x31 / 0x70 in the data

Transaction (what the chain stores) =  (..., ephemeral)
   ephemeral = ML-KEM ciphertext (768 bytes)  [shared secret for all stealth
              outputs in this tx; empty for txs with no stealth outputs]

On-chain output (what the chain sees) =  (value, HASH160(R))
   R        = WOTS+ public root of a fresh one-time key
              derived at index `i` from the tx's shared secret
```

### Aggregated ephemeral (one ciphertext per transaction)
Instead of attaching a 768-byte ciphertext to every stealth output (which
duplicated the blob when one transaction paid several stealth outputs), the
ciphertext lives in `Transaction.ephemeral`. A single transaction that pays
`N` stealth outputs therefore spends **one** 768-byte capsule instead of `N`.
Each output `i` derives its one-time WOTS+ key at index `i`:

```
shared_i = KEM.decaps(dk, tx.ephemeral)        // same secret for all outputs
wots_i   = WotsKeypair::derive(SHA-256("litc-stealth-v1" || shared_i), i)
script_i = HASH160(wots_i.R)
```

Non-stealth (legacy single-use) transactions simply have `ephemeral = []`.

## Protocol

### Key setup (recipient)
1. From the wallet master seed, derive a 64-byte KEM seed and build an
   **ML-KEM-512** keypair: encapsulation key `pk` (800 B) and decapsulation
   key `dk` (64 B seed). The decapsulation key is the **scan key**.
 2. Encode `pk` as the reusable address (Bech32m, HRP `litc`/`tlitc`):
    `stealth_address(pk, version)`.

### Sending (sender)
1. Decode the recipient's stealth address to get `pk`.
2. Encapsulate once: `(shared, ct) = KEM.encaps(pk)`.
3. For output `i` (0-based position in `tx.outputs`), derive a one-time WOTS+
   key from the shared secret:
   `stealth_seed = SHA-256("litc-stealth-v1" || shared)`;
   `wots_i = WotsKeypair::derive(stealth_seed, i)`.
4. Build each output as `value`, `script = HASH160(wots_i.R)` (no per-output
   ciphertext), and set `tx.ephemeral = ct`.

### Scanning (recipient wallet)
1. Walk every UTXO via `UtxoStore::iter_utxos`, which now yields
   `(OutPoint, TxOut, ephemeral)`.
2. For each output whose `ephemeral` is non-empty, decapsulate with the
   **output's index** `i = outpoint.index`:
   `shared = dk.decaps(ephemeral)`;
   `wots_i = WotsKeypair::derive(SHA-256("litc-stealth-v1"||shared), i)`.
3. Check `HASH160(wots_i.R) == output.script`. On match, the output is yours.
4. Persist the recovered key as a `StealthKey` record in the `KeyStore` so it
   survives restarts (the scan key alone cannot spend after a reload).

### Spending (recipient)
- `spend_stealth(outpoint, to_commit)` signs a spend with the recovered WOTS+
  key, revealing `R` as usual. The one-time rule still applies, so each stealth
  output is spent exactly once.

## Security properties
- **Reusable UX, one-time chain keys.** The recipient's published address never
  changes; each payment lands on an unlinkable `HASH160(R)`.
- **Post-quantum.** ML-KEM-512 (FIPS 203) + WOTS+ are both quantum-resistant.
- **No extra trust.** The KEM only hides the link between address and output;
  it never signs. Spending still requires the WOTS+ key uniquely tied to that
  output.
- **Stateless wallet.** The KEM seed and every WOTS+ key are derived from the
  single master seed; nothing must be persisted to stay correct — only the
  recovered spend keys are cached for convenience.

## Code layout

`crates/litc-primitives/src/lib.rs`
- `mod kem` — thin wrapper over `ml-kem` 0.3:
  - `kem_keypair_from_seed(seed: &[u8;32]) -> ([u8;800], [u8;64])`
  - `kem_encaps(pk: &[u8;800]) -> ([u8;32], [u8;768])`
  - `kem_decaps(sk: &[u8;64], ct: &[u8;768]) -> [u8;32]`
- `mod stealth` — protocol glue:
  - `stealth_seed(shared) -> [u8;32]`
  - `stealth_script(shared, index) -> [u8;20]`
  - `stealth_address(kem_pk, version) -> String`
  - `parse_stealth_address(s) -> Option<(u8, [u8;800])>`  (returns the address
    version alongside the KEM public key)
  - `build_stealth_output(kem_pk, value) -> (TxOut, [u8;768])`  (output
    + the tx-level ciphertext; script is `stealth_script(shared, 0)`)
  - `recover_stealth_keypair(kem_sk, ct) -> Option<WotsKeypair>` (index 0)
  - `recover_stealth_keypair_at(kem_sk, ct, index) -> Option<WotsKeypair>`

`crates/litc-store/src/lib.rs`
- `UtxoStore::iter_utxos -> Vec<(OutPoint, TxOut, Vec<u8>)>` — enumerate all
  unspent outputs **with** their tx-level ephemeral ciphertext.
- `UtxoStore::add_utxo(outpoint, output, ephemeral)` — the `ephemeral` comes
  from `tx.ephemeral` and is persisted in `utxo.dat`.

`crates/litc-keystore/src/lib.rs`
- `StealthKey { commit, sk_seed, pk_seed, r }` (116 B) + `load_stealth` /
  `save_stealth`. Persisted in `wallet.dat.stealth`.

`crates/litc-wallet/src/lib.rs`
- `kem_keypair`, `stealth_address`, `send_stealth`, `scan_chain`,
  `spend_stealth`, and `OwnedStealth` (the per-output scan result).

## Constants
- `KEM_PK_LEN = 800`, `KEM_SK_LEN = 64` (decapsulation seed), `KEM_CT_LEN = 768`,
  `KEM_SS_LEN = 32`.
- `STEALTH_VERSION_MAINNET = 0x31`, `STEALTH_VERSION_TESTNET = 0x70`.
