# FFI — using LiTC from any language

`litc-ffi` is a `#[no_mangle]` C-ABI crate built as both a `cdylib`
(`liblitc_ffi.so` / `.dylib` / `.dll`) and a `staticlib`
(`liblitc_ffi.a`). Any language with a C FFI can link it: C/C++,
Python (`ctypes`/`cffi`), Go (`cgo`), Rust (`extern "C"`), Zig, Swift,
Nim, etc.

## Building

```bash
cargo build -p litc-ffi                 # release: --release
# outputs:  target/debug/liblitc_ffi.so (+ .a)
# headers:  crates/litc-ffi/include/litc.h
```

## Conventions

- Return codes: functions returning `int` use `0` = OK, `-1` = error.
  On error, `litc_last_error()` returns a heap-allocated C string
  (free with `litc_string_free`).
- Fixed-size outputs use caller-owned buffers: you pass `out`/`out_len`
  and the function fills `out_len` bytes.
- Variable-size outputs are `(ptr, len)` blobs allocated by the library;
  free with `litc_free(ptr, len)`. Strings use `litc_string_free`.
- All `len` arguments are sizes in **bytes**, not elements.

## API surface (`include/litc.h`)

Cryptography (no chain state required):

| Function | Purpose |
|----------|---------|
| `litc_random_seed(out, 32)` | 32-byte RNG seed for key derivation |
| `litc_kem_keypair(seed, pk, sk)` | ML-KEM-512 keypair from a seed |
| `litc_kem_encaps(pk, out_ss, out_ct)` | encapsulate a shared secret |
| `litc_kem_decaps(sk, ct, out_ss)` | decapsulate (recipient only) |
| `litc_wots_commit(seed, index, out_commit)` | WOTS+ commitment (20-byte address) |
| `litc_wots_address(seed, index, ver, *out_addr)` | base58check address from a commit |
| `litc_wots_sign(seed, index, msg, out_sig, cap, *len)` | one-time signature |
| `litc_wots_verify(commit, msg, sig, sig_len)` | verify a signature |
| `litc_stealth_address(pk, ver, *out_addr)` | reusable stealth address (800 B) |
| `litc_parse_stealth_address(s, pk, *testnet)` | decode an address back to a pk |
| `litc_stealth_build_output(pk, value, *out_bytes, *len, *out_ct, *ct_len)` | one-time output **and** the tx-level ciphertext |
| `litc_stealth_commit(sk, ct, index, out_commit)` | recipient commitment from sk+ct at `index` |
| `litc_stealth_sign(sk, ct, index, msg, out_sig, cap, *len)` | sign a stealth spend at `index` |
| `litc_txout_decode(bytes, len, *value, out_commit, *out_ephemeral, *eph_len)` | recover output fields |

Helper sizes: `litc_kem_pk_len()`, `litc_kem_sk_len()`,
`litc_kem_ct_len()`, `litc_kem_ss_len()`, `litc_wots_sig_len()`.

## Language sizes (constant, see `docs/stealth.md`)

`KEM_PK=800  KEM_SK=64  KEM_CT=768  KEM_SS=32  WOTS_SIG=1152  COMMIT=20`.

> `litc_stealth_build_output` returns **both** the serialized `TxOut` and the
> KEM ciphertext (`out_ct`). Store `out_ct` in the transaction's `ephemeral`
> field — that is what the recipient passes to `litc_stealth_commit` /
> `litc_stealth_sign`. The output itself carries no ciphertext.

## C example

`crates/litc-ffi/examples/example.c` exercises the whole flow
(stealth address → one-time output → decode → sign → verify):

```bash
cc examples/example.c -I include -L ../../target/debug -llitc_ffi -o demo
LD_LIBRARY_PATH=../../target/debug ./demo
```
