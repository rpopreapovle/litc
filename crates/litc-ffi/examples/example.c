/*
 * Minimal LiTC FFI example: WOTS+ + ML-KEM-512 stealth address round trip.
 *
 * Build (Linux):
 *   cargo build -p litc-ffi
 *   cc examples/example.c -Iinclude \
 *      ../target/debug/liblitc_ffi.so -o example && ./example
 *
 * Or link the staticlib: -L../target/debug -llitc_ffi -lpthread -ldl -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "litc.h"

static void die(const char *step)
{
    char buf[256];
    litc_last_error(buf, sizeof(buf));
    fprintf(stderr, "error at %s: %s\n", step, buf);
    exit(1);
}

#define CHECK(step, rc) do { if ((rc) != 0) die(step); } while (0)

int main(void)
{
    uint8_t seed[32];
    CHECK("random_seed", litc_random_seed(seed));

    uint8_t pk[800], sk[64];
    CHECK("kem_keypair", litc_kem_keypair(seed, pk, sk));

    char *addr = NULL;
    CHECK("stealth_address", litc_stealth_address(pk, 0, &addr));
    printf("stealth address: %s\n", addr);

    uint8_t pk2[800];
    uint8_t testnet = 0;
    CHECK("parse_stealth_address",
          litc_parse_stealth_address(addr, pk2, &testnet));
    if (memcmp(pk, pk2, sizeof(pk)) != 0) die("roundtrip pk mismatch");
    litc_string_free(addr);

    /* Build a one-time output + its transaction-level ciphertext. */
    uint8_t *out_bytes = NULL, *ct = NULL;
    size_t out_len = 0, ct_len = 0;
    uint64_t value = 123456789ULL;
    CHECK("stealth_build_output",
          litc_stealth_build_output(pk, value, &out_bytes, &out_len,
                                    &ct, &ct_len));

    /* Decode the output to confirm the value and recover the commitment. */
    uint64_t dec_value = 0;
    uint8_t dec_commit[20];
    uint8_t *dec_eph = NULL;
    size_t dec_eph_len = 0;
    CHECK("txout_decode",
          litc_txout_decode(out_bytes, out_len, &dec_value, dec_commit,
                            &dec_eph, &dec_eph_len));
    if (dec_value != value) die("value mismatch");
    if (dec_eph_len != 0) die("expected empty per-output ephemeral");
    litc_free(dec_eph, dec_eph_len);
    litc_free(out_bytes, out_len);

    /* Recover the commitment from the scan secret + ciphertext (index 0). */
    uint8_t rec_commit[20];
    CHECK("stealth_commit",
          litc_stealth_commit(sk, ct, 0, rec_commit));
    if (memcmp(rec_commit, dec_commit, 20) != 0) die("commit mismatch");

    /* Sign a spend and verify it. */
    uint8_t sighash[32];
    memset(sighash, 0xab, sizeof(sighash));
    size_t sig_len = 0;
    uint8_t *sig = malloc(litc_wots_sig_len());
    CHECK("stealth_sign",
          litc_stealth_sign(sk, ct, 0, sighash, sig, litc_wots_sig_len(),
                            &sig_len));
    if (litc_wots_verify(rec_commit, sighash, sig, sig_len) != 1)
        die("verify failed");
    free(sig);

    litc_free(ct, ct_len);
    printf("OK: stealth output built, recovered, signed, and verified.\n");
    return 0;
}
