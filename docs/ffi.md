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
| `litc_mldsa_keypair(seed, pk, sk)` | ML-DSA-2 keypair from a 32-byte seed |
| `litc_mldsa_address(pk, ver, *out_addr)` | bech32m address from a public key |
| `litc_mldsa_sign(sk, msg, out_sig, cap, *len)` | sign a 32-byte message |
| `litc_mldsa_verify(pk, msg, sig, sig_len)` | verify a signature |
| `litc_parse_address(s, *out_hash, *testnet)` | decode an address back to HASH160(pk) |

Helper sizes: `litc_mldsa_pk_len()` (1312), `litc_mldsa_sig_len()` (2420).

## Language sizes (constant)

`MLDSA_PK=1312  MLDSA_SIG=2420  MLDSA_SEED=32  HASH160=20`.
