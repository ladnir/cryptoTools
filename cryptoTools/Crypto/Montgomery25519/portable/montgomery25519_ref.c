/***************************************************************************
 * The Montgomery ladder and small-order blocklist follow the modified
 * osu-crypto/libsodium Curve25519 noclamp implementation (ISC license).
 * Field operations use cryptoTools' portable radix-2^51 implementation.
 ***************************************************************************/

#include "montgomery25519_ref.h"

#include <stddef.h>
#include <string.h>

#include <cryptoTools/Crypto/Edwards25519/portable/fe25519.h>

int osuCrypto_montgomery25519_has_small_order_ref(
    const unsigned char s[32])
{
    static const unsigned char blocklist[][32] = {
        { 0x00 },
        { 0x01 },
        { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
          0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
          0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
          0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
        { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
          0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
          0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
          0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
        { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
    };
    unsigned char differences[7] = { 0 };
    unsigned int any_equal = 0;
    size_t i, j;

    for (j = 0; j != 31; ++j)
        for (i = 0; i != 7; ++i)
            differences[i] |= s[j] ^ blocklist[i][j];
    for (i = 0; i != 7; ++i)
        differences[i] |= (s[31] & 0x7f) ^ blocklist[i][31];
    for (i = 0; i != 7; ++i)
        any_equal |= (unsigned int)(differences[i] - 1U);
    return (int)((any_equal >> 8) & 1U);
}

int osuCrypto_montgomery25519_scalarmult_ref(
    unsigned char q[32], const unsigned char n[32],
    const unsigned char p[32])
{
    unsigned char scalar[32];
    fe25519 x1, x2, x3, z2, z3;
    fe25519 a, b, aa, bb, e, da, cb;
    unsigned int swap = 0;
    int pos;

    if (osuCrypto_montgomery25519_has_small_order_ref(p))
        return -1;

    memcpy(scalar, n, sizeof(scalar));
    scalar[31] &= 0x7f;
    fe25519_unpack(&x1, p);
    fe25519_setint(&x2, 1);
    fe25519_setint(&z2, 0);
    x3 = x1;
    fe25519_setint(&z3, 1);

    for (pos = 254; pos >= 0; --pos) {
        const unsigned int bit =
            (unsigned int)((scalar[pos >> 3] >> (pos & 7)) & 1);
        swap ^= bit;
        fe25519_cswap(&x2, &x3, (unsigned char)swap);
        fe25519_cswap(&z2, &z3, (unsigned char)swap);
        swap = bit;
        fe25519_add(&a, &x2, &z2);
        fe25519_sub(&b, &x2, &z2);
        fe25519_square(&aa, &a);
        fe25519_square(&bb, &b);
        fe25519_mul(&x2, &aa, &bb);
        fe25519_sub(&e, &aa, &bb);
        fe25519_sub(&da, &x3, &z3);
        fe25519_mul(&da, &da, &a);
        fe25519_add(&cb, &x3, &z3);
        fe25519_mul(&cb, &cb, &b);
        fe25519_add(&x3, &da, &cb);
        fe25519_square(&x3, &x3);
        fe25519_sub(&z3, &da, &cb);
        fe25519_square(&z3, &z3);
        fe25519_mul(&z3, &z3, &x1);
        fe25519_mul121666(&z2, &e);
        fe25519_add(&z2, &z2, &bb);
        fe25519_mul(&z2, &z2, &e);
    }
    fe25519_cswap(&x2, &x3, (unsigned char)swap);
    fe25519_cswap(&z2, &z3, (unsigned char)swap);
    fe25519_invert(&z2, &z2);
    fe25519_mul(&x2, &x2, &z2);
    fe25519_pack(q, &x2);

    {
        unsigned char nonzero = 0;
        size_t i;
        for (i = 0; i != 32; ++i)
            nonzero |= q[i];
        return nonzero == 0 ? -1 : 0;
    }
}
