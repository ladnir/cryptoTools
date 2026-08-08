/*************************************************************************
* SPDX-License-Identifier: Apache-2.0
*
* Copyright (C) Intel Corporation
* Copyright osuCrypto contributors
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may
* not use this file except in compliance with the License. You may obtain
* a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
*
* The radix-2^52 multiplication and reduction schedule is derived from
* Intel Cryptography Primitives. The Edwards25519 point arithmetic and
* cryptoTools integration are original to this file.
*************************************************************************/

#include "ge8x_ifma.h"

#include <array>
#include <cstdint>
#include <cstring>

namespace
{
    using Vec = __m512i;
    using Fe = gfe8x;
    using Ge = ge8x;
    using Mask = __mmask8;

    constexpr std::uint64_t mask52 = (std::uint64_t{1} << 52) - 1;
    constexpr std::uint64_t mask47 = (std::uint64_t{1} << 47) - 1;
    constexpr std::uint64_t pLo = 0x000fffffffffffedULL;
    constexpr std::uint64_t pMid = 0x000fffffffffffffULL;
    constexpr std::uint64_t pHi = 0x00007fffffffffffULL;

#if defined(_MSC_VER)
#define IFMA_NOINLINE __declspec(noinline)
#else
#define IFMA_NOINLINE __attribute__((noinline))
#endif

    inline Vec zero() { return _mm512_setzero_si512(); }
    inline Vec set1(std::uint64_t x) { return _mm512_set1_epi64(static_cast<long long>(x)); }
    inline Vec maddLo(Vec acc, Vec a, Vec b) { return _mm512_madd52lo_epu64(acc, a, b); }
    inline Vec maddHi(Vec acc, Vec a, Vec b) { return _mm512_madd52hi_epu64(acc, a, b); }

    inline void normalizeLogical(Vec& r0, Vec& r1, Vec& r2, Vec& r3, Vec& r4)
    {
        const Vec m52 = set1(mask52);
        r1 = _mm512_add_epi64(r1, _mm512_srli_epi64(r0, 52));
        r0 = _mm512_and_si512(r0, m52);
        r2 = _mm512_add_epi64(r2, _mm512_srli_epi64(r1, 52));
        r1 = _mm512_and_si512(r1, m52);
        r3 = _mm512_add_epi64(r3, _mm512_srli_epi64(r2, 52));
        r2 = _mm512_and_si512(r2, m52);
        r4 = _mm512_add_epi64(r4, _mm512_srli_epi64(r3, 52));
        r3 = _mm512_and_si512(r3, m52);
    }

    inline void normalizeArithmetic(Vec& r0, Vec& r1, Vec& r2, Vec& r3, Vec& r4)
    {
        const Vec m52 = set1(mask52);
        r1 = _mm512_add_epi64(r1, _mm512_srai_epi64(r0, 52));
        r0 = _mm512_and_si512(r0, m52);
        r2 = _mm512_add_epi64(r2, _mm512_srai_epi64(r1, 52));
        r1 = _mm512_and_si512(r1, m52);
        r3 = _mm512_add_epi64(r3, _mm512_srai_epi64(r2, 52));
        r2 = _mm512_and_si512(r2, m52);
        r4 = _mm512_add_epi64(r4, _mm512_srai_epi64(r3, 52));
        r3 = _mm512_and_si512(r3, m52);
    }

    inline Fe feZero()
    {
        const Vec z = zero();
        return {{z, z, z, z, z}};
    }

    inline Fe feOne()
    {
        Fe r = feZero();
        r.limb[0] = set1(1);
        return r;
    }

    inline void feAdd(Fe& r, const Fe& a, const Fe& b)
    {
        Vec r0 = _mm512_add_epi64(a.limb[0], b.limb[0]);
        Vec r1 = _mm512_add_epi64(a.limb[1], b.limb[1]);
        Vec r2 = _mm512_add_epi64(a.limb[2], b.limb[2]);
        Vec r3 = _mm512_add_epi64(a.limb[3], b.limb[3]);
        Vec r4 = _mm512_add_epi64(a.limb[4], b.limb[4]);
        Vec t0 = _mm512_sub_epi64(r0, set1(pLo));
        Vec t1 = _mm512_sub_epi64(r1, set1(pMid));
        Vec t2 = _mm512_sub_epi64(r2, set1(pMid));
        Vec t3 = _mm512_sub_epi64(r3, set1(pMid));
        Vec t4 = _mm512_sub_epi64(r4, set1(pHi));
        normalizeLogical(r0, r1, r2, r3, r4);
        normalizeArithmetic(t0, t1, t2, t3, t4);
        const Mask under = _mm512_cmp_epi64_mask(t4, zero(), _MM_CMPINT_LT);
        r.limb[0] = _mm512_mask_mov_epi64(t0, under, r0);
        r.limb[1] = _mm512_mask_mov_epi64(t1, under, r1);
        r.limb[2] = _mm512_mask_mov_epi64(t2, under, r2);
        r.limb[3] = _mm512_mask_mov_epi64(t3, under, r3);
        r.limb[4] = _mm512_mask_mov_epi64(t4, under, r4);
    }

    inline void feSub(Fe& r, const Fe& a, const Fe& b)
    {
        Vec r0 = _mm512_sub_epi64(a.limb[0], b.limb[0]);
        Vec r1 = _mm512_sub_epi64(a.limb[1], b.limb[1]);
        Vec r2 = _mm512_sub_epi64(a.limb[2], b.limb[2]);
        Vec r3 = _mm512_sub_epi64(a.limb[3], b.limb[3]);
        Vec r4 = _mm512_sub_epi64(a.limb[4], b.limb[4]);
        Vec t0 = _mm512_add_epi64(r0, set1(pLo));
        Vec t1 = _mm512_add_epi64(r1, set1(pMid));
        Vec t2 = _mm512_add_epi64(r2, set1(pMid));
        Vec t3 = _mm512_add_epi64(r3, set1(pMid));
        Vec t4 = _mm512_add_epi64(r4, set1(pHi));
        normalizeArithmetic(r0, r1, r2, r3, r4);
        normalizeArithmetic(t0, t1, t2, t3, t4);
        const Mask under = _mm512_cmp_epi64_mask(r4, zero(), _MM_CMPINT_LT);
        r.limb[0] = _mm512_mask_mov_epi64(r0, under, t0);
        r.limb[1] = _mm512_mask_mov_epi64(r1, under, t1);
        r.limb[2] = _mm512_mask_mov_epi64(r2, under, t2);
        r.limb[3] = _mm512_mask_mov_epi64(r3, under, t3);
        r.limb[4] = _mm512_mask_mov_epi64(r4, under, t4);
    }

    inline void feNeg(Fe& r, const Fe& a)
    {
        const Vec z = zero();
        const Vec p0 = set1(pLo), pm = set1(pMid), p4 = set1(pHi);
        const Vec any = _mm512_or_si512(
            _mm512_or_si512(a.limb[0], a.limb[1]),
            _mm512_or_si512(_mm512_or_si512(a.limb[2], a.limb[3]), a.limb[4]));
        const Mask nonzero = _mm512_cmp_epi64_mask(any, z, _MM_CMPINT_NE);
        r.limb[0] = _mm512_mask_sub_epi64(a.limb[0], nonzero, p0, a.limb[0]);
        r.limb[1] = _mm512_mask_sub_epi64(a.limb[1], nonzero, pm, a.limb[1]);
        r.limb[2] = _mm512_mask_sub_epi64(a.limb[2], nonzero, pm, a.limb[2]);
        r.limb[3] = _mm512_mask_sub_epi64(a.limb[3], nonzero, pm, a.limb[3]);
        r.limb[4] = _mm512_mask_sub_epi64(a.limb[4], nonzero, p4, a.limb[4]);
        normalizeArithmetic(
            r.limb[0], r.limb[1], r.limb[2], r.limb[3], r.limb[4]);
    }

#define MUL_ROUND(I, J, LO, HI)         \
    do {                                \
        LO = maddLo(LO, a.limb[I], b.limb[J]); \
        HI = maddHi(HI, a.limb[I], b.limb[J]); \
    } while (false)

#define REDUCE_ROUND(LO, NEXT, HIGH)                           \
    do {                                                       \
        LO = maddLo(LO, HIGH, c608);                            \
        NEXT = maddLo(maddHi(NEXT, HIGH, c608),                \
                      _mm512_srli_epi64(HIGH, 52), c608);       \
    } while (false)

    IFMA_NOINLINE void feMul(Fe& out, const Fe& a, const Fe& b)
    {
        const Vec z = zero(), c19 = set1(19), c608 = set1(19 * 32);
        Vec r0 = z, r1 = z, r2 = z, r3 = z, r4 = z;
        Vec r5 = z, r6 = z, r7 = z, r8 = z, r9 = z;
        MUL_ROUND(4, 4, r8, r9);
        MUL_ROUND(3, 0, r3, r4); MUL_ROUND(1, 2, r3, r4);
        MUL_ROUND(0, 3, r3, r4); MUL_ROUND(2, 1, r3, r4);
        MUL_ROUND(2, 2, r4, r5); MUL_ROUND(0, 4, r4, r5);
        MUL_ROUND(1, 3, r4, r5); MUL_ROUND(3, 1, r4, r5);
        MUL_ROUND(4, 0, r4, r5); MUL_ROUND(1, 4, r5, r6);
        MUL_ROUND(2, 3, r5, r6); MUL_ROUND(3, 2, r5, r6);
        MUL_ROUND(4, 1, r5, r6); MUL_ROUND(2, 4, r6, r7);
        MUL_ROUND(3, 3, r6, r7); MUL_ROUND(4, 2, r6, r7);
        MUL_ROUND(0, 0, r0, r1); MUL_ROUND(0, 1, r1, r2);
        MUL_ROUND(0, 2, r2, r3); MUL_ROUND(1, 0, r1, r2);
        MUL_ROUND(1, 1, r2, r3); MUL_ROUND(2, 0, r2, r3);
        MUL_ROUND(3, 4, r7, r8); MUL_ROUND(4, 3, r7, r8);
        r4 = maddLo(r4, r9, c608);
        r0 = maddLo(r0, _mm512_srli_epi64(r4, 47), c19);
        r4 = _mm512_and_si512(r4, set1(mask47));
        REDUCE_ROUND(r0, r1, r5); REDUCE_ROUND(r1, r2, r6);
        REDUCE_ROUND(r2, r3, r7); REDUCE_ROUND(r3, r4, r8);
        normalizeLogical(r0, r1, r2, r3, r4);
        out = {{r0, r1, r2, r3, r4}};
    }

    IFMA_NOINLINE void feSquare(Fe& out, const Fe& a)
    {
        const Vec z = zero(), c19 = set1(19), c608 = set1(19 * 32);
        const Fe& b = a;
        Vec r0 = z, r1 = z, r2 = z, r3 = z, r4 = z;
        Vec r5 = z, r6 = z, r7 = z, r8 = z, r9 = z;
        MUL_ROUND(0, 1, r1, r2); MUL_ROUND(0, 2, r2, r3);
        MUL_ROUND(0, 3, r3, r4); MUL_ROUND(0, 4, r4, r5);
        MUL_ROUND(1, 4, r5, r6); MUL_ROUND(2, 4, r6, r7);
        MUL_ROUND(3, 4, r7, r8); MUL_ROUND(1, 2, r3, r4);
        MUL_ROUND(1, 3, r4, r5); MUL_ROUND(2, 3, r5, r6);
        r1 = _mm512_add_epi64(r1, r1); r2 = _mm512_add_epi64(r2, r2);
        r3 = _mm512_add_epi64(r3, r3); r4 = _mm512_add_epi64(r4, r4);
        r5 = _mm512_add_epi64(r5, r5); r6 = _mm512_add_epi64(r6, r6);
        r7 = _mm512_add_epi64(r7, r7); r8 = _mm512_add_epi64(r8, r8);
        MUL_ROUND(0, 0, r0, r1); MUL_ROUND(1, 1, r2, r3);
        MUL_ROUND(2, 2, r4, r5); MUL_ROUND(3, 3, r6, r7);
        MUL_ROUND(4, 4, r8, r9);
        r4 = maddLo(r4, r9, c608);
        r0 = maddLo(r0, _mm512_srli_epi64(r4, 47), c19);
        r4 = _mm512_and_si512(r4, set1(mask47));
        REDUCE_ROUND(r0, r1, r5); REDUCE_ROUND(r1, r2, r6);
        REDUCE_ROUND(r2, r3, r7); REDUCE_ROUND(r3, r4, r8);
        normalizeLogical(r0, r1, r2, r3, r4);
        out = {{r0, r1, r2, r3, r4}};
    }

#undef REDUCE_ROUND
#undef MUL_ROUND

    inline void feSquareN(Fe& out, const Fe& a, unsigned count)
    {
        Fe t = a;
        while (count--)
            feSquare(t, t);
        out = t;
    }

    void fePow2523(Fe& out, const Fe& z)
    {
        Fe t0, t1, t2;
        feSquare(t0, z);
        feSquareN(t1, t0, 2);
        feMul(t1, z, t1);
        feMul(t0, t0, t1);
        feSquare(t0, t0);
        feMul(t0, t1, t0);
        feSquareN(t1, t0, 5); feMul(t0, t1, t0);
        feSquareN(t1, t0, 10); feMul(t1, t1, t0);
        feSquareN(t2, t1, 20); feMul(t1, t2, t1);
        feSquareN(t1, t1, 10); feMul(t0, t1, t0);
        feSquareN(t1, t0, 50); feMul(t1, t1, t0);
        feSquareN(t2, t1, 100); feMul(t1, t2, t1);
        feSquareN(t1, t1, 50); feMul(t0, t1, t0);
        feSquareN(t0, t0, 2); feMul(out, t0, z);
    }

    void feInvert(Fe& out, const Fe& z)
    {
        Fe t0, t1, t2, t3;
        feSquare(t0, z);
        feSquare(t1, t0); feSquare(t1, t1);
        feMul(t1, z, t1); feMul(t0, t0, t1);
        feSquare(t2, t0); feMul(t1, t1, t2);
        feSquareN(t2, t1, 5); feMul(t1, t2, t1);
        feSquareN(t2, t1, 10); feMul(t2, t2, t1);
        feSquareN(t3, t2, 20); feMul(t2, t3, t2);
        feSquareN(t2, t2, 10); feMul(t1, t2, t1);
        feSquareN(t2, t1, 50); feMul(t2, t2, t1);
        feSquareN(t3, t2, 100); feMul(t2, t3, t2);
        feSquareN(t2, t2, 50); feMul(t1, t2, t1);
        feSquareN(t1, t1, 5); feMul(out, t1, t0);
    }

    inline void feReduce(Fe& out, const Fe& a)
    {
        Vec r0 = _mm512_sub_epi64(a.limb[0], set1(pLo));
        Vec r1 = _mm512_sub_epi64(a.limb[1], set1(pMid));
        Vec r2 = _mm512_sub_epi64(a.limb[2], set1(pMid));
        Vec r3 = _mm512_sub_epi64(a.limb[3], set1(pMid));
        Vec r4 = _mm512_sub_epi64(a.limb[4], set1(pHi));
        normalizeArithmetic(r0, r1, r2, r3, r4);
        const Mask under = _mm512_cmp_epi64_mask(r4, zero(), _MM_CMPINT_LT);
        out.limb[0] = _mm512_mask_mov_epi64(r0, under, a.limb[0]);
        out.limb[1] = _mm512_mask_mov_epi64(r1, under, a.limb[1]);
        out.limb[2] = _mm512_mask_mov_epi64(r2, under, a.limb[2]);
        out.limb[3] = _mm512_mask_mov_epi64(r3, under, a.limb[3]);
        out.limb[4] = _mm512_mask_mov_epi64(r4, under, a.limb[4]);
    }

    inline Mask feEqual(const Fe& a, const Fe& b)
    {
        Fe ar, br;
        feReduce(ar, a); feReduce(br, b);
        Vec d = _mm512_xor_si512(ar.limb[0], br.limb[0]);
        d = _mm512_or_si512(d, _mm512_xor_si512(ar.limb[1], br.limb[1]));
        d = _mm512_or_si512(d, _mm512_xor_si512(ar.limb[2], br.limb[2]));
        d = _mm512_or_si512(d, _mm512_xor_si512(ar.limb[3], br.limb[3]));
        d = _mm512_or_si512(d, _mm512_xor_si512(ar.limb[4], br.limb[4]));
        return _mm512_cmp_epi64_mask(d, zero(), _MM_CMPINT_EQ);
    }

    inline Mask feParity(const Fe& a)
    {
        Fe t;
        feReduce(t, a);
        return _mm512_cmp_epi64_mask(
            _mm512_and_si512(t.limb[0], set1(1)), set1(1), _MM_CMPINT_EQ);
    }

    inline Mask feCanonical(const Fe& a)
    {
        Mask equal = static_cast<Mask>(0xff);
        Mask less = 0;
        less = static_cast<Mask>(less | (equal & _mm512_cmp_epu64_mask(
            a.limb[4], set1(pHi), _MM_CMPINT_LT)));
        equal = static_cast<Mask>(equal & _mm512_cmp_epi64_mask(
            a.limb[4], set1(pHi), _MM_CMPINT_EQ));
        less = static_cast<Mask>(less | (equal & _mm512_cmp_epu64_mask(
            a.limb[3], set1(pMid), _MM_CMPINT_LT)));
        equal = static_cast<Mask>(equal & _mm512_cmp_epi64_mask(
            a.limb[3], set1(pMid), _MM_CMPINT_EQ));
        less = static_cast<Mask>(less | (equal & _mm512_cmp_epu64_mask(
            a.limb[2], set1(pMid), _MM_CMPINT_LT)));
        equal = static_cast<Mask>(equal & _mm512_cmp_epi64_mask(
            a.limb[2], set1(pMid), _MM_CMPINT_EQ));
        less = static_cast<Mask>(less | (equal & _mm512_cmp_epu64_mask(
            a.limb[1], set1(pMid), _MM_CMPINT_LT)));
        equal = static_cast<Mask>(equal & _mm512_cmp_epi64_mask(
            a.limb[1], set1(pMid), _MM_CMPINT_EQ));
        less = static_cast<Mask>(less | (equal & _mm512_cmp_epu64_mask(
            a.limb[0], set1(pLo), _MM_CMPINT_LT)));
        return less;
    }

    inline void feCmov(Fe& r, const Fe& a, Mask select)
    {
        for (unsigned i = 0; i != 5; ++i)
            r.limb[i] = _mm512_mask_mov_epi64(r.limb[i], select, a.limb[i]);
    }

    inline Fe feFrom51(const fe25519 input[8])
    {
        alignas(64) std::uint64_t limb[5][8];
        for (unsigned lane = 0; lane != 8; ++lane)
        {
            const auto* a = input[lane].v;
            limb[0][lane] = a[0] | ((a[1] & 1) << 51);
            limb[1][lane] = (a[1] >> 1) | ((a[2] & 3) << 50);
            limb[2][lane] = (a[2] >> 2) | ((a[3] & 7) << 49);
            limb[3][lane] = (a[3] >> 3) | ((a[4] & 15) << 48);
            limb[4][lane] = a[4] >> 4;
        }
        Fe r;
        for (unsigned i = 0; i != 5; ++i)
            r.limb[i] = _mm512_load_si512(limb[i]);
        return r;
    }

    inline Fe feBroadcast51(const fe25519& input)
    {
        const auto* a = input.v;
        Fe r;
        r.limb[0] = set1(a[0] | ((a[1] & 1) << 51));
        r.limb[1] = set1((a[1] >> 1) | ((a[2] & 3) << 50));
        r.limb[2] = set1((a[2] >> 2) | ((a[3] & 7) << 49));
        r.limb[3] = set1((a[3] >> 3) | ((a[4] & 15) << 48));
        r.limb[4] = set1(a[4] >> 4);
        return r;
    }

    inline Fe feConstant51(const std::uint64_t (&a)[5])
    {
        fe25519 t = {{a[0], a[1], a[2], a[3], a[4]}};
        return feBroadcast51(t);
    }

    inline Fe feFromBytes(const unsigned char encoded[8 * 32])
    {
        alignas(64) std::uint64_t words[4][8];
        for (unsigned lane = 0; lane != 8; ++lane)
        {
            std::memcpy(&words[0][lane], encoded + lane * 32 + 0, 8);
            std::memcpy(&words[1][lane], encoded + lane * 32 + 8, 8);
            std::memcpy(&words[2][lane], encoded + lane * 32 + 16, 8);
            std::memcpy(&words[3][lane], encoded + lane * 32 + 24, 8);
            words[3][lane] &= 0x7fffffffffffffffULL;
        }
        const Vec w0 = _mm512_load_si512(words[0]);
        const Vec w1 = _mm512_load_si512(words[1]);
        const Vec w2 = _mm512_load_si512(words[2]);
        const Vec w3 = _mm512_load_si512(words[3]);
        const Vec m52 = set1(mask52);
        Fe r;
        r.limb[0] = _mm512_and_si512(w0, m52);
        r.limb[1] = _mm512_and_si512(
            _mm512_or_si512(_mm512_srli_epi64(w0, 52), _mm512_slli_epi64(w1, 12)), m52);
        r.limb[2] = _mm512_and_si512(
            _mm512_or_si512(_mm512_srli_epi64(w1, 40), _mm512_slli_epi64(w2, 24)), m52);
        r.limb[3] = _mm512_and_si512(
            _mm512_or_si512(_mm512_srli_epi64(w2, 28), _mm512_slli_epi64(w3, 36)), m52);
        r.limb[4] = _mm512_and_si512(_mm512_srli_epi64(w3, 16), set1(mask47));
        return r;
    }

    inline void feToWords(std::uint64_t words[4][8], const Fe& input)
    {
        Fe a;
        feReduce(a, input);
        const Vec w0 = _mm512_or_si512(a.limb[0], _mm512_slli_epi64(a.limb[1], 52));
        const Vec w1 = _mm512_or_si512(_mm512_srli_epi64(a.limb[1], 12), _mm512_slli_epi64(a.limb[2], 40));
        const Vec w2 = _mm512_or_si512(_mm512_srli_epi64(a.limb[2], 24), _mm512_slli_epi64(a.limb[3], 28));
        const Vec w3 = _mm512_or_si512(_mm512_srli_epi64(a.limb[3], 36), _mm512_slli_epi64(a.limb[4], 16));
        _mm512_store_si512(words[0], w0); _mm512_store_si512(words[1], w1);
        _mm512_store_si512(words[2], w2); _mm512_store_si512(words[3], w3);
    }

    inline void geCmov(Ge& r, const Ge& a, Mask select)
    {
        feCmov(r.x, a.x, select); feCmov(r.y, a.y, select);
        feCmov(r.z, a.z, select); feCmov(r.t, a.t, select);
    }

    inline void geNeg(Ge& r, const Ge& p)
    {
        r = p;
        feNeg(r.x, p.x); feNeg(r.t, p.t);
    }

    void geAddImpl(Ge& r, const Ge& p, const Ge& q)
    {
        static const std::uint64_t d51[5] = {
            929955233495203ULL, 466365720129213ULL, 1662059464998953ULL,
            2033849074728123ULL, 1442794654840575ULL};
        const Fe d = feConstant51(d51);
        Fe twoD; feAdd(twoD, d, d);
        Fe a, b, c, dd, e, f, g, h, t0, t1;
        feSub(t0, p.y, p.x); feSub(t1, q.y, q.x); feMul(a, t0, t1);
        feAdd(t0, p.y, p.x); feAdd(t1, q.y, q.x); feMul(b, t0, t1);
        feMul(t0, p.t, q.t); feMul(c, t0, twoD);
        feMul(dd, p.z, q.z); feAdd(dd, dd, dd);
        feSub(e, b, a); feSub(f, dd, c); feAdd(g, dd, c); feAdd(h, b, a);
        feMul(r.x, e, f); feMul(r.y, g, h);
        feMul(r.t, e, h); feMul(r.z, f, g);
    }

    void geDoubleImpl(Ge& r, const Ge& p)
    {
        Fe a, b, c, d, e, f, g, h, t;
        feSquare(a, p.x); feSquare(b, p.y); feSquare(c, p.z); feAdd(c, c, c);
        feNeg(d, a); feAdd(t, p.x, p.y); feSquare(e, t);
        feSub(e, e, a); feSub(e, e, b); feAdd(g, d, b);
        feSub(f, g, c); feSub(h, d, b);
        feMul(r.x, e, f); feMul(r.y, g, h);
        feMul(r.t, e, h); feMul(r.z, f, g);
    }

    void makeMultiples(Ge table[8], const Ge& p)
    {
        table[0] = p;
        geDoubleImpl(table[1], p);
        geAddImpl(table[2], table[1], p);
        geDoubleImpl(table[3], table[1]);
        geAddImpl(table[4], table[3], p);
        geDoubleImpl(table[5], table[2]);
        geAddImpl(table[6], table[5], p);
        geDoubleImpl(table[7], table[3]);
    }

    Ge selectMultiple(const Ge table[8], const signed char digits[8])
    {
        alignas(64) std::int64_t values[8];
        for (unsigned lane = 0; lane != 8; ++lane)
            values[lane] = digits[lane];
        Vec d = _mm512_load_si512(values);
        const Mask negative = _mm512_cmp_epi64_mask(d, zero(), _MM_CMPINT_LT);
        d = _mm512_mask_sub_epi64(d, negative, zero(), d);
        Ge r;
        ge8x_setneutral(&r);
        for (std::uint64_t i = 1; i <= 8; ++i)
            geCmov(r, table[i - 1], _mm512_cmp_epi64_mask(d, set1(i), _MM_CMPINT_EQ));
        Ge neg;
        geNeg(neg, r);
        geCmov(r, neg, negative);
        return r;
    }

    void scalarWindows(signed char windows[8][64], const sc25519 scalars[8])
    {
        for (unsigned lane = 0; lane != 8; ++lane)
            sc25519_window4(windows[lane], &scalars[lane]);
    }

    Ge scalarMultiply(const Ge& p, const sc25519 scalars[8])
    {
        Ge table[8];
        makeMultiples(table, p);
        signed char windows[8][64];
        scalarWindows(windows, scalars);
        signed char digits[8];
        for (unsigned lane = 0; lane != 8; ++lane) digits[lane] = windows[lane][63];
        Ge result = selectMultiple(table, digits);
        for (int bit = 62; bit >= 0; --bit)
        {
            geDoubleImpl(result, result); geDoubleImpl(result, result);
            geDoubleImpl(result, result); geDoubleImpl(result, result);
            for (unsigned lane = 0; lane != 8; ++lane) digits[lane] = windows[lane][bit];
            const Ge selected = selectMultiple(table, digits);
            geAddImpl(result, result, selected);
        }
        return result;
    }

    struct BaseTable
    {
        Ge row[32][8];

        BaseTable()
        {
            Ge p;
            alignas(64) unsigned char encoded[8 * 32];
            for (unsigned lane = 0; lane != 8; ++lane)
            {
                encoded[lane * 32] = 0x58;
                std::memset(encoded + lane * 32 + 1, 0x66, 31);
            }
            (void)ge8x_unpack_vartime(&p, encoded);
            for (unsigned i = 0; i != 32; ++i)
            {
                makeMultiples(row[i], p);
                if (i + 1 != 32)
                {
                    geDoubleImpl(p, row[i][7]);
                    geDoubleImpl(p, p); geDoubleImpl(p, p);
                    geDoubleImpl(p, p); geDoubleImpl(p, p);
                }
            }
        }
    };

    const BaseTable& baseTable()
    {
        static const BaseTable table;
        return table;
    }

#undef IFMA_NOINLINE
}

extern "C" void ge8x_setneutral(ge8x* r)
{
    r->x = feZero(); r->y = feOne(); r->z = feOne(); r->t = feZero();
}

extern "C" void ge8x_from_ge25519(ge8x* r, const ge25519* p)
{
    r->x = feBroadcast51(p->x); r->y = feBroadcast51(p->y);
    r->z = feBroadcast51(p->z); r->t = feBroadcast51(p->t);
}

extern "C" void ge8x_add(ge8x* r, const ge8x* p, const ge8x* q)
{
    Ge out;
    geAddImpl(out, *p, *q);
    *r = out;
}

extern "C" void ge8x_sub(ge8x* r, const ge8x* p, const ge8x* q)
{
    Ge neg;
    geNeg(neg, *q);
    ge8x_add(r, p, &neg);
}

extern "C" void ge8x_double(ge8x* r, const ge8x* p)
{
    Ge out;
    geDoubleImpl(out, *p);
    *r = out;
}

extern "C" void ge8x_cmovs(ge8x* r, const ge8x* p, const unsigned char select[8])
{
    Mask mask = 0;
    for (unsigned lane = 0; lane != 8; ++lane)
        mask = static_cast<Mask>(mask | ((select[lane] & 1) << lane));
    geCmov(*r, *p, mask);
}

extern "C" void ge8x_map_to_curve_elligator2(ge8x* r, const fe25519 input[8])
{
    static const std::uint64_t c2_51[5] = {
        1718705420411057ULL, 234908883556509ULL, 2233514472574048ULL,
        2117202627021982ULL, 765476049583133ULL};
    static const std::uint64_t sqrtM1_51[5] = {
        1718705420411056ULL, 234908883556509ULL, 2233514472574048ULL,
        2117202627021982ULL, 765476049583133ULL};
    static const std::uint64_t sqrtMinus486664_51[5] = {
        1693982333959686ULL, 608509411481997ULL, 2235573344831311ULL,
        947681270984193ULL, 266558006233600ULL};
    const Fe u = feFrom51(input), c2 = feConstant51(c2_51);
    const Fe sqrtM1 = feConstant51(sqrtM1_51);
    const Fe sqrtMinus486664 = feConstant51(sqrtMinus486664_51);
    Fe tv1, tv2, tv3, xd, x1n, gxd, gx1, y11, y12, x2n;
    Fe y21, y22, gx2, y1, y2, yneg, xmn, ymn, xn, xdn, yn, yd;
    const Fe one = feOne(), zeroFe = feZero();
    Fe j = feZero(); j.limb[0] = set1(486662);
    feSquare(tv1, u); feAdd(tv1, tv1, tv1); feAdd(xd, tv1, one);
    feNeg(x1n, j); feSquare(tv2, xd); feMul(gxd, tv2, xd);
    feMul(gx1, j, tv1); feMul(gx1, gx1, x1n); feAdd(gx1, gx1, tv2);
    feMul(gx1, gx1, x1n); feSquare(tv3, gxd); feSquare(tv2, tv3);
    feMul(tv3, tv3, gxd); feMul(tv3, tv3, gx1); feMul(tv2, tv2, tv3);
    fePow2523(y11, tv2); feMul(y11, y11, tv3); feMul(y12, y11, sqrtM1);
    feSquare(tv2, y11); feMul(tv2, tv2, gxd);
    const Mask e1 = feEqual(tv2, gx1);
    y1 = y12; feCmov(y1, y11, e1);
    feMul(x2n, x1n, tv1); feMul(y21, y11, u); feMul(y21, y21, c2);
    feMul(y22, y21, sqrtM1); feMul(gx2, gx1, tv1);
    feSquare(tv2, y21); feMul(tv2, tv2, gxd);
    const Mask e2 = feEqual(tv2, gx2);
    y2 = y22; feCmov(y2, y21, e2);
    feSquare(tv2, y1); feMul(tv2, tv2, gxd);
    const Mask e3 = feEqual(tv2, gx1);
    xmn = x2n; feCmov(xmn, x1n, e3);
    ymn = y2; feCmov(ymn, y1, e3);
    const Mask e4 = feParity(ymn);
    feNeg(yneg, ymn); feCmov(ymn, yneg, static_cast<Mask>(e3 ^ e4));
    xn = xmn; feMul(xn, xn, sqrtMinus486664); feMul(xdn, xd, ymn);
    feSub(yn, xmn, xd); feAdd(yd, xmn, xd); feMul(tv1, xdn, yd);
    const Mask exceptional = feEqual(tv1, zeroFe);
    feCmov(xn, zeroFe, exceptional); feCmov(xdn, one, exceptional);
    feCmov(yn, one, exceptional); feCmov(yd, one, exceptional);
    feMul(r->x, xn, yd); feMul(r->y, yn, xdn);
    feMul(r->z, xdn, yd); feMul(r->t, xn, yn);
}

extern "C" int ge8x_unpack_vartime(ge8x* r, const unsigned char encoded[8 * 32])
{
    static const std::uint64_t d51[5] = {
        929955233495203ULL, 466365720129213ULL, 1662059464998953ULL,
        2033849074728123ULL, 1442794654840575ULL};
    static const std::uint64_t sqrtM1_51[5] = {
        1718705420411056ULL, 234908883556509ULL, 2233514472574048ULL,
        2117202627021982ULL, 765476049583133ULL};
    const Fe d = feConstant51(d51), sqrtM1 = feConstant51(sqrtM1_51);
    const Fe y = feFromBytes(encoded), one = feOne();
    const Mask canonical = feCanonical(y);
    Fe u, v, v3, x, vxx, check, xAlt;
    feSquare(u, y); feMul(v, u, d); feSub(u, u, one); feAdd(v, v, one);
    feSquare(v3, v); feMul(v3, v3, v);
    feSquare(x, v3); feMul(x, x, v); feMul(x, x, u);
    fePow2523(x, x); feMul(x, x, v3); feMul(x, x, u);
    feSquare(vxx, x); feMul(vxx, vxx, v);
    feSub(check, vxx, u); const Mask k1 = feEqual(check, feZero());
    feAdd(check, vxx, u); const Mask k2 = feEqual(check, feZero());
    xAlt = x; feMul(xAlt, xAlt, sqrtM1);
    Ge out; ge8x_setneutral(&out);
    feCmov(out.x, x, static_cast<Mask>(k1 & canonical));
    feCmov(out.x, xAlt, static_cast<Mask>(k2 & canonical));
    Mask valid = static_cast<Mask>((k1 | k2) & canonical);
    feCmov(out.y, y, valid);
    Mask sign = 0;
    for (unsigned lane = 0; lane != 8; ++lane)
        sign = static_cast<Mask>(sign | ((encoded[lane * 32 + 31] >> 7) << lane));
    Fe negX; feNeg(negX, out.x);
    feCmov(out.x, negX, static_cast<Mask>(sign ^ feParity(out.x)));
    valid = static_cast<Mask>(valid & ~(sign & feEqual(out.x, feZero())));
    feMul(out.t, out.x, out.y);
    Ge checked;
    ge8x_setneutral(&checked);
    geCmov(checked, out, valid);
    *r = checked;
    return valid == static_cast<Mask>(0xff) ? 0 : -1;
}

extern "C" void ge8x_pack(unsigned char encoded[8 * 32], const ge8x* p)
{
    Fe recip, x, y;
    feInvert(recip, p->z); feMul(x, p->x, recip); feMul(y, p->y, recip);
    alignas(64) std::uint64_t words[4][8];
    feToWords(words, y);
    const Mask sign = feParity(x);
    for (unsigned lane = 0; lane != 8; ++lane)
    {
        words[3][lane] |= std::uint64_t((sign >> lane) & 1) << 63;
        std::memcpy(encoded + lane * 32 + 0, &words[0][lane], 8);
        std::memcpy(encoded + lane * 32 + 8, &words[1][lane], 8);
        std::memcpy(encoded + lane * 32 + 16, &words[2][lane], 8);
        std::memcpy(encoded + lane * 32 + 24, &words[3][lane], 8);
    }
}

extern "C" void ge8x_scalarmult(ge8x* r, const ge8x* p, const sc25519* scalar)
{
    sc25519 scalars[8];
    for (auto& s : scalars) s = *scalar;
    *r = scalarMultiply(*p, scalars);
}

extern "C" void ge8x_scalarsmults(ge8x* r, const ge8x* p, const sc25519 scalars[8])
{
    *r = scalarMultiply(*p, scalars);
}

extern "C" void ge8x_scalarsmults_base(ge8x* r, const sc25519 scalars[8])
{
    signed char windows[8][64], digits[8];
    scalarWindows(windows, scalars);
    const auto& table = baseTable();
    for (unsigned lane = 0; lane != 8; ++lane) digits[lane] = windows[lane][0];
    Ge even = selectMultiple(table.row[0], digits);
    for (unsigned lane = 0; lane != 8; ++lane) digits[lane] = windows[lane][1];
    Ge odd = selectMultiple(table.row[0], digits);
    for (unsigned row = 1; row != 32; ++row)
    {
        for (unsigned lane = 0; lane != 8; ++lane) digits[lane] = windows[lane][2 * row];
        Ge selected = selectMultiple(table.row[row], digits);
        geAddImpl(even, even, selected);
        for (unsigned lane = 0; lane != 8; ++lane) digits[lane] = windows[lane][2 * row + 1];
        selected = selectMultiple(table.row[row], digits);
        geAddImpl(odd, odd, selected);
    }
    geDoubleImpl(odd, odd); geDoubleImpl(odd, odd);
    geDoubleImpl(odd, odd); geDoubleImpl(odd, odd);
    geAddImpl(*r, odd, even);
}
