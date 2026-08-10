#ifndef CRYPTOTOOLS_MONTGOMERY25519_ASM_H
#define CRYPTOTOOLS_MONTGOMERY25519_ASM_H

#ifdef __cplusplus
extern "C" {
#endif

// Four independent unclamped Montgomery25519 scalar multiplications using
// cryptoTools' four-lane assembly field backend. Return bit i is one exactly
// when lane i has a nonzero result.
unsigned char montgomery25519_asm4_scalarsmults(
    unsigned char output[4 * 32],
    const unsigned char points[4 * 32],
    const unsigned char scalars[4 * 32]);

// As above, with one scalar broadcast across all four lanes.
unsigned char montgomery25519_asm4_scalarmult(
    unsigned char output[4 * 32],
    const unsigned char points[4 * 32],
    const unsigned char scalar[32]);

// Eight independent multiplications. The two four-lane ladders share their
// final inversion using Montgomery's trick. Inputs must all produce nonzero
// projective Z coordinates; return 0xff on success and another value otherwise.
unsigned char montgomery25519_asm8_scalarsmults(
    unsigned char output[8 * 32],
    const unsigned char points[8 * 32],
    const unsigned char scalars[8 * 32]);

// As above, with one scalar broadcast across all eight lanes.
unsigned char montgomery25519_asm8_scalarmult(
    unsigned char output[8 * 32],
    const unsigned char points[8 * 32],
    const unsigned char scalar[32]);

#ifdef __cplusplus
}
#endif

#endif
