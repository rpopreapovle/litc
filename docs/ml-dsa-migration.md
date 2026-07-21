# ML-DSA-2 (Dilithium) — Replacement Plan

Network is not live. **No migration needed.** Direct replacement of WOTS+ +
ML-KEM with ML-DSA-2 (NIST FIPS 204).

## What changes

| Component | Before | After |
|-----------|--------|-------|
| Signature scheme | WOTS+ (one-time, ~2.2KB sig) | ML-DSA-2 (reusable, ~2.4KB sig) |
| Address format | base58check `L…`/`m…` (~34 chars) | bech32m `litc1q…` (~40 chars) |
| Stealth addresses | ML-KEM-512 + stealth scan | **Deleted** |
| KEM | `kem.rs` — ML-KEM-512 wrapper | **Deleted** |
| Burnt keys | burnt-keys index in store | **Deleted** |
| Tx ephemeral | 768B KEM ciphertext | Always empty |

## Crate

`ml-dsa` from RustCrypto (FIPS 204). NOT `pqcrypto-dilithium` (pre-FIPS).

```toml
ml-dsa = "0.1"
```

## Files to modify/delete

**Delete:**
- `crates/litc-primitives/src/kem.rs`
- `crates/litc-primitives/src/stealth.rs`

**Rewrite:**
- `crates/litc-primitives/src/lib.rs` — replace WOTS+ module with ML-DSA-2, remove KEM/stealth modules, update SignatureScheme enum
- `crates/litc-wallet/src/lib.rs` — remove stealth scan/send/spend, simplify to ML-DSA-2
- `crates/litc-keystore/src/lib.rs` — remove StealthKey, load/save_stealth, load/save_used
- `crates/litc-store/src/lib.rs` — remove BurntKeys, ephemeral UTXO tracking, burnt.dat persistence
- `crates/litc-store/src/state.rs` — remove burnt from state root, remove burnt SMT
- `crates/litc-core/src/lib.rs` — update validate_tx, remove burnt-key checks
- `crates/litc-cli/src/main.rs` — update wallet commands (remove stealth subcommands)
- `crates/litc-ffi/src/lib.rs` — remove KEM/stealth FFI, update WOTS+ FFI to ML-DSA-2
- `crates/litc-lightwallet/src/lib.rs` — remove stealth, update to ML-DSA-2
- `crates/litc-node/src/lib.rs` — remove stealth coinbase output, update imports
- `crates/litc-node/src/rpc.rs` — remove stealth RPC methods
- `crates/litc-miner/src/lib.rs` — remove coinbase_ephemeral field

**Update:**
- `crates/litc-primitives/Cargo.toml` — replace `ml-kem` with `ml-dsa`
- `docs/specification.md` — ML-DSA-2 everywhere
- `docs/wallet.md` — new address format, remove stealth refs
- `docs/uri.md` — update address examples
- `docs/state.md` — remove burnt keys from root description
- `docs/cli.md` — remove stealth subcommands
- `docs/rpc.md` — remove stealth RPC methods
- `docs/ffi.md` — remove WOTS+/KEM/stealth API docs

**Archive:**
- `docs/stealth.md` → historical
- `docs/wots.md` → historical
