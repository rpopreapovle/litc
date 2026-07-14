/*
 * LiTC FFI — C ABI header.
 *
 * Companion to the `litc-ffi` cdylib/staticlib (`liblitc_ffi`). Every function
 * returns 0 on success and -1 on error; the last error is retrievable with
 * `litc_last_error`. Fixed-size outputs use caller-owned buffers; variable-size
 * outputs are `(ptr, len)` blobs you free with `litc_free` (strings with
 * `litc_string_free`). All `len` values are byte counts.
 *
 * Constant sizes (see docs/stealth.md):
 *   KEM_PK = 800   KEM_SK = 64   KEM_CT = 768   KEM_SS = 32
 *   WOTS_SIG = (2 + L) * N  (L=34, N=32 => 1152)   COMMIT = 20
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

size_t litc_kem_pk_len(void);
size_t litc_kem_sk_len(void);
size_t litc_kem_ct_len(void);
size_t litc_kem_ss_len(void);
size_t litc_wots_sig_len(void);

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
/* WOTS+ (one-time signatures)                                             */
/* ----------------------------------------------------------------------- */

/* Derive the 20-byte commitment (HASH160(R)) for `seed` at `index`. */
int litc_wots_commit(const uint8_t *seed, uint32_t index, uint8_t *out_commit);

/* Build a base58check WOTS+ address from `seed` at `index`.
 * `*out_addr` is heap-allocated; free with `litc_string_free`. */
int litc_wots_address(const uint8_t *seed, uint32_t index, uint8_t testnet,
                      char **out_addr);

/* Sign `msg` (32 bytes) with the one-time key `seed`/`index`.
 * `out_sig` must hold `litc_wots_sig_len()` bytes; `*out_len` is set. */
int litc_wots_sign(const uint8_t *seed, uint32_t index, const uint8_t *msg,
                   uint8_t *out_sig, size_t sig_cap, size_t *out_len);

/* Verify `sig` (length `sig_len`) over `msg` (32 bytes) for `commit` (20 B).
 * Returns 1 if valid, 0 otherwise. */
int litc_wots_verify(const uint8_t *commit, const uint8_t *msg,
                     const uint8_t *sig, size_t sig_len);

/* ----------------------------------------------------------------------- */
/* ML-KEM-512 (post-quantum KEM)                                           */
/* ----------------------------------------------------------------------- */

/* Derive an ML-KEM-512 keypair (pk = 800 B, sk = 64 B) from a 32-byte seed. */
int litc_kem_keypair(const uint8_t *seed, uint8_t *out_pk, uint8_t *out_sk);

/* Encapsulate: produce shared secret `out_ss` (32 B) and ciphertext `out_ct`
 * (768 B) for `pk`. */
int litc_kem_encaps(const uint8_t *pk, uint8_t *out_ss, uint8_t *out_ct);

/* Decapsulate: recover the shared secret `out_ss` (32 B) from `ct` (768 B)
 * using `sk`. Recipient side only. */
int litc_kem_decaps(const uint8_t *sk, const uint8_t *ct, uint8_t *out_ss);

/* ----------------------------------------------------------------------- */
/* Stealth addresses (reusable, post-quantum)                             */
/* ----------------------------------------------------------------------- */

/* Build a reusable stealth address (800 B KEM pk) as a base58check string.
 * `*out_addr` is heap-allocated; free with `litc_string_free`. */
int litc_stealth_address(const uint8_t *pk, uint8_t testnet, char **out_addr);

/* Decode a stealth address back into the 800-byte `pk` and a `out_testnet`
 * flag (1 = testnet). */
int litc_parse_stealth_address(const char *addr, uint8_t *out_pk,
                               uint8_t *out_testnet);

/* Build a one-time output script paying `pk` with `value_sat` satoshis.
 * Returns the serialized TxOut in `*out_bytes` (free with `litc_free`) AND the
 * KEM ciphertext in `*out_ct` (free with `litc_free`). The ciphertext must be
 * stored in the transaction's `ephemeral` field so the recipient can recover
 * the same shared secret. The capsule is randomized, so the script and
 * ciphertext come from one encapsulation and must stay paired. */
int litc_stealth_build_output(const uint8_t *pk, uint64_t value_sat,
                              uint8_t **out_bytes, size_t *out_len,
                              uint8_t **out_ct, size_t *out_ct_len);

/* Recover the 20-byte commitment for an output at `index` from the scan
 * secret `sk` and the transaction's `ct` (768 B). */
int litc_stealth_commit(const uint8_t *sk, const uint8_t *ct, uint32_t index,
                        uint8_t *out_commit);

/* Sign a stealth spend of the output at `index`: shared secret from `ct`
 * (768 B) decrypted with `sk`, message `msg` (32 B). `out_sig` must hold
 * `litc_wots_sig_len()` bytes; `*out_len` is set. */
int litc_stealth_sign(const uint8_t *sk, const uint8_t *ct, uint32_t index,
                      const uint8_t *msg, uint8_t *out_sig, size_t sig_cap,
                      size_t *out_len);

/* ----------------------------------------------------------------------- */
/* TxOut inspection                                                        */
/* ----------------------------------------------------------------------- */

/* Decode a serialized TxOut. Writes `out_value` (satoshis) and the 20-byte
 * `out_commit`; `out_ephemeral`/`out_ephemeral_len` receive the (usually
 * empty) per-output ciphertext blob, freed with `litc_free`. */
int litc_txout_decode(const uint8_t *bytes, size_t len, uint64_t *out_value,
                      uint8_t *out_commit, uint8_t **out_ephemeral,
                      size_t *out_ephemeral_len);

#ifdef __cplusplus
}
#endif

#endif /* LITC_FFI_H */
