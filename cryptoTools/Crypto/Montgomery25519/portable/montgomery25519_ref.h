#ifndef CRYPTOTOOLS_MONTGOMERY25519_REF_H
#define CRYPTOTOOLS_MONTGOMERY25519_REF_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Multiply an arbitrary Montgomery u-coordinate by an unclamped 255-bit
 * scalar. The high bit of both inputs is ignored, matching the modified
 * libsodium crypto_scalarmult_noclamp() contract.
 *
 * Returns 0 on success and -1 for a small-order input or zero output.
 */
int osuCrypto_montgomery25519_scalarmult_ref(
    unsigned char q[32], const unsigned char n[32],
    const unsigned char p[32]);

int osuCrypto_montgomery25519_has_small_order_ref(
    const unsigned char p[32]);

#ifdef __cplusplus
}
#endif

#endif
