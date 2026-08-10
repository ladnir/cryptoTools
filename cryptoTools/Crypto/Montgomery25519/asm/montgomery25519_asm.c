#include "montgomery25519_asm.h"

#ifdef CRYPTOTOOLS_EDWARDS25519_ASM

#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>

#include <cryptoTools/Crypto/Edwards25519/batch/gfe4x.h>

extern const limb scale19;
extern const limb _4x121666;
extern const limb alpha22;
extern const limb alpha43;
extern const limb alpha64;
extern const limb alpha85;
extern const limb alpha107;
extern const limb alpha128;
extern const limb alpha149;
extern const limb alpha170;
extern const limb alpha192;
extern const limb alpha213;
extern const limb alpha234;
extern const limb alpha255;

static void gfe4x_swap(
    gfe4x* first, gfe4x* second, const unsigned char select[4])
{
    union {
        uint64_t bits[4];
        __m256d vector;
    } mask;
    size_t limb_index;

    mask.bits[0] = (uint64_t)0 - (uint64_t)select[0];
    mask.bits[1] = (uint64_t)0 - (uint64_t)select[1];
    mask.bits[2] = (uint64_t)0 - (uint64_t)select[2];
    mask.bits[3] = (uint64_t)0 - (uint64_t)select[3];
    for (limb_index = 0; limb_index != 12; ++limb_index)
    {
        const __m256d first_value =
            _mm256_load_pd(first->v[limb_index].v);
        const __m256d second_value =
            _mm256_load_pd(second->v[limb_index].v);
        const __m256d difference = _mm256_and_pd(
            _mm256_xor_pd(first_value, second_value), mask.vector);
        _mm256_store_pd(first->v[limb_index].v,
            _mm256_xor_pd(first_value, difference));
        _mm256_store_pd(second->v[limb_index].v,
            _mm256_xor_pd(second_value, difference));
    }
}

static void gfe4x_mul121666(gfe4x* output, const gfe4x* input)
{
    __m256d value[12];
    __m256d carry;
    const __m256d multiplier = _mm256_load_pd(_4x121666.v);
    size_t limb_index;

    for (limb_index = 0; limb_index != 12; ++limb_index)
        value[limb_index] = _mm256_mul_pd(
            _mm256_load_pd(input->v[limb_index].v), multiplier);

#define CARRY_LIMB(index, alpha) \
    carry = _mm256_sub_pd( \
        _mm256_add_pd(value[index], _mm256_load_pd(alpha.v)), \
        _mm256_load_pd(alpha.v)); \
    value[index] = _mm256_sub_pd(value[index], carry); \
    value[(index) + 1] = _mm256_add_pd(value[(index) + 1], carry)

    CARRY_LIMB(0, alpha22);
    CARRY_LIMB(1, alpha43);
    CARRY_LIMB(2, alpha64);
    CARRY_LIMB(3, alpha85);
    CARRY_LIMB(4, alpha107);
    CARRY_LIMB(5, alpha128);
    CARRY_LIMB(6, alpha149);
    CARRY_LIMB(7, alpha170);
    CARRY_LIMB(8, alpha192);
    CARRY_LIMB(9, alpha213);
    CARRY_LIMB(10, alpha234);

    carry = _mm256_sub_pd(
        _mm256_add_pd(value[11], _mm256_load_pd(alpha255.v)),
        _mm256_load_pd(alpha255.v));
    value[11] = _mm256_sub_pd(value[11], carry);
    value[0] = _mm256_add_pd(value[0],
        _mm256_mul_pd(carry, _mm256_load_pd(scale19.v)));

    CARRY_LIMB(0, alpha22);
#undef CARRY_LIMB

    for (limb_index = 0; limb_index != 12; ++limb_index)
        _mm256_store_pd(output->v[limb_index].v, value[limb_index]);
}

static void montgomery25519_ladder4(
    gfe4x* x2,
    gfe4x* z2,
    const unsigned char points[4 * 32],
    const unsigned char* scalars,
    size_t scalar_stride)
{
    gfe4x x1, x3, z3;
    gfe4x a, b, aa, bb, e, da, cb;
    unsigned char swap[4] = { 0, 0, 0, 0 };
    unsigned char select[4];
    const unsigned char* scalar0 = scalars;
    const unsigned char* scalar1 = scalars + scalar_stride;
    const unsigned char* scalar2 = scalars + 2 * scalar_stride;
    const unsigned char* scalar3 = scalars + 3 * scalar_stride;
    int bit_position;

    gfe4x_unpack(&x1, points);
    gfe4x_setone(x2);
    gfe4x_setzero(z2);
    x3 = x1;
    gfe4x_setone(&z3);

    for (bit_position = 254; bit_position >= 0; --bit_position)
    {
        const size_t byte = (size_t)bit_position >> 3;
        const unsigned int shift = (unsigned int)bit_position & 7;
        const unsigned char bit0 =
            (unsigned char)((scalar0[byte] >> shift) & 1);
        const unsigned char bit1 =
            (unsigned char)((scalar1[byte] >> shift) & 1);
        const unsigned char bit2 =
            (unsigned char)((scalar2[byte] >> shift) & 1);
        const unsigned char bit3 =
            (unsigned char)((scalar3[byte] >> shift) & 1);
        select[0] = (unsigned char)(swap[0] ^ bit0);
        select[1] = (unsigned char)(swap[1] ^ bit1);
        select[2] = (unsigned char)(swap[2] ^ bit2);
        select[3] = (unsigned char)(swap[3] ^ bit3);
        swap[0] = bit0;
        swap[1] = bit1;
        swap[2] = bit2;
        swap[3] = bit3;
        gfe4x_swap(x2, &x3, select);
        gfe4x_swap(z2, &z3, select);

        gfe4x_add(&a, x2, z2);
        gfe4x_sub(&b, x2, z2);
        gfe4x_square(&aa, &a);
        gfe4x_square(&bb, &b);
        gfe4x_mul(x2, &aa, &bb);
        gfe4x_sub(&e, &aa, &bb);
        gfe4x_sub(&da, &x3, &z3);
        gfe4x_mul(&da, &da, &a);
        gfe4x_add(&cb, &x3, &z3);
        gfe4x_mul(&cb, &cb, &b);
        gfe4x_add(&x3, &da, &cb);
        gfe4x_square(&x3, &x3);
        gfe4x_sub(&z3, &da, &cb);
        gfe4x_square(&z3, &z3);
        gfe4x_mul(&z3, &z3, &x1);
        gfe4x_mul121666(z2, &e);
        gfe4x_add(z2, z2, &bb);
        gfe4x_mul(z2, z2, &e);
    }
    gfe4x_swap(x2, &x3, swap);
    gfe4x_swap(z2, &z3, swap);
}

static unsigned char montgomery25519_pack4(
    unsigned char output[4 * 32], gfe4x* x, const gfe4x* inverse_z)
{
    size_t lane;

    gfe4x_mul(x, x, inverse_z);
    gfe4x_pack(output, x);

    {
        unsigned char valid = 0;
        for (lane = 0; lane != 4; ++lane)
        {
            unsigned char nonzero = 0;
            size_t byte;
            for (byte = 0; byte != 32; ++byte)
                nonzero |= output[lane * 32 + byte];
            valid |= (unsigned char)((nonzero != 0) << lane);
        }
        return valid;
    }
}

static unsigned char montgomery25519_asm4_impl(
    unsigned char output[4 * 32],
    const unsigned char points[4 * 32],
    const unsigned char* scalars,
    size_t scalar_stride)
{
    gfe4x x, z, inverse_z;

    montgomery25519_ladder4(&x, &z, points, scalars, scalar_stride);
    gfe4x_invert(&inverse_z, &z);
    return montgomery25519_pack4(output, &x, &inverse_z);
}

static unsigned char montgomery25519_asm8_impl(
    unsigned char output[8 * 32],
    const unsigned char points[8 * 32],
    const unsigned char* scalars,
    size_t scalar_stride)
{
    gfe4x x[2], z[2];
    gfe4x product, inverse, inverse_z[2];
    unsigned char low, high;

    montgomery25519_ladder4(
        &x[0], &z[0], points, scalars, scalar_stride);
    montgomery25519_ladder4(
        &x[1], &z[1], points + 4 * 32,
        scalars + 4 * scalar_stride, scalar_stride);

    /* Montgomery's trick: one inversion for both four-lane batches. */
    gfe4x_mul(&product, &z[0], &z[1]);
    gfe4x_invert(&inverse, &product);
    gfe4x_mul(&inverse_z[0], &inverse, &z[1]);
    gfe4x_mul(&inverse_z[1], &inverse, &z[0]);

    low = montgomery25519_pack4(output, &x[0], &inverse_z[0]);
    high = montgomery25519_pack4(
        output + 4 * 32, &x[1], &inverse_z[1]);
    return (unsigned char)(low | (unsigned char)(high << 4));
}

unsigned char montgomery25519_asm4_scalarsmults(
    unsigned char output[4 * 32],
    const unsigned char points[4 * 32],
    const unsigned char scalars[4 * 32])
{
    return montgomery25519_asm4_impl(output, points, scalars, 32);
}

unsigned char montgomery25519_asm4_scalarmult(
    unsigned char output[4 * 32],
    const unsigned char points[4 * 32],
    const unsigned char scalar[32])
{
    return montgomery25519_asm4_impl(output, points, scalar, 0);
}

unsigned char montgomery25519_asm8_scalarsmults(
    unsigned char output[8 * 32],
    const unsigned char points[8 * 32],
    const unsigned char scalars[8 * 32])
{
    return montgomery25519_asm8_impl(output, points, scalars, 32);
}

unsigned char montgomery25519_asm8_scalarmult(
    unsigned char output[8 * 32],
    const unsigned char points[8 * 32],
    const unsigned char scalar[32])
{
    return montgomery25519_asm8_impl(output, points, scalar, 0);
}

#endif
