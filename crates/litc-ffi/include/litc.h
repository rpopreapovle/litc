/*
 * LiTC FFI — C ABI header.
 *
 * Companion to the `litc-ffi` cdylib/staticlib (`liblitc_ffi`). Every function
 * returns 0 on success and -1 on error; the last error is retrievable with
 * `litc_last_error`. Fixed-size outputs use caller-owned buffers; variable-size
 * outputs are `(ptr, len)` blobs you free with `litc_free` (strings with
 * `litc_string_free`). All `len` values are byte counts.
 *
 * ML-DSA-2 sizes:
 *   PK = 1312   SIG = 2420   SEED = 32   COMMIT = 20
 */

#ifndef LITC_FFI_H
#define LITC_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------- */
/* Sizes                                                                   */
/* ----------------------------------------------------------------------- */

size_t litc_mldsa_pk_len(void);
size_t litc_mldsa_sig_len(void);

/* ----------------------------------------------------------------------- */
/* Error handling / memory                                                 */
/* ----------------------------------------------------------------------- */

/* Copy the last error message into `buf` (max `len` bytes, including NUL).
 * Returns the number of bytes written (excluding NUL), 0 if no error. */
size_t litc_last_error(char *buf, size_t len);

/* Free a variable-size blob returned by the library. `len` must be the exact
 * length returned alongside the pointer; pass 0 only if the pointer is NULL. */
void litc_free(void *ptr, size_t len);

/* Free a C string returned by the library (e.g. an address). */
void litc_string_free(char *s);

/* ----------------------------------------------------------------------- */
/* Randomness                                                              */
/* ----------------------------------------------------------------------- */

/* Fill `seed_out` (32 bytes) with an OS RNG seed for key derivation. */
int litc_random_seed(uint8_t *seed_out);

/* ----------------------------------------------------------------------- */
/* ML-DSA-2 (post-quantum signatures)                                      */
/* ----------------------------------------------------------------------- */

/* Derive an ML-DSA-2 keypair from `seed` (32 bytes).
 * `out_pk` must hold 1312 bytes; `out_sk` must hold 32 bytes. */
int litc_mldsa_keypair(const uint8_t *seed, uint8_t *out_pk, uint8_t *out_sk);

/* Build a bech32m ML-DSA-2 address from `seed` at `index`.
 * `testnet`: nonzero for testnet ("tlitc1..."), zero for mainnet ("litc1...").
 * `*out_addr` is heap-allocated; free with `litc_string_free`. */
int litc_mldsa_address(const uint8_t *seed, uint32_t index, uint8_t testnet,
                       char **out_addr);

/* Sign `msg` (32 bytes) with the ML-DSA-2 key derived from `seed`/`index`.
 * `out_sig` must hold `litc_mldsa_sig_len()` bytes; `*out_len` is set. */
int litc_mldsa_sign(const uint8_t *seed, uint32_t index, const uint8_t *msg,
                    uint8_t *out_sig, size_t sig_cap, size_t *out_len);

/* Verify `sig` (length `sig_len`) over `msg` (32 bytes) against `pk` (1312 B).
 * Returns 1 if valid, 0 otherwise. */
int litc_mldsa_verify(const uint8_t *pk, const uint8_t *msg,
                      const uint8_t *sig, size_t sig_len);

/* Decode a bech32m ML-DSA-2 address. Writes the 20-byte HASH160(pk) into
 * `out_hash` and sets `*out_testnet` to 1 (testnet) or 0 (mainnet). */
int litc_parse_address(const char *addr, uint8_t *out_hash,
                       uint8_t *out_testnet);

/* ----------------------------------------------------------------------- */
/* TxOut inspection                                                        */
/* ----------------------------------------------------------------------- */

/* Decode a serialized TxOut. Writes `out_value` (satoshis) and the 20-byte
 * `out_commit` (first 20 bytes of the script). */
int litc_txout_decode(const uint8_t *bytes, size_t len, uint64_t *out_value,
                      uint8_t *out_commit);

#ifdef __cplusplus
}
#endif

#endif /* LITC_FFI_H */
