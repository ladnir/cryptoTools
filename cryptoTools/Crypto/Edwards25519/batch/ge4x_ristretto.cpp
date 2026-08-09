/* SPDX-License-Identifier: ISC
 *
 * Four-lane Ristretto255 formulas corresponding to portable/ristretto255.c.
 * Field operations remain in gfe4x form throughout each map or codec call.
 */
#include "ge4x.h"

#include <cstdint>
#include <cstring>

namespace
{
    const fe25519 sqrtM1Scalar = {{
        1718705420411056ULL, 234908883556509ULL, 2233514472574048ULL,
        2117202627021982ULL, 765476049583133ULL}};
    const fe25519 dScalar = {{
        929955233495203ULL, 466365720129213ULL, 1662059464998953ULL,
        2033849074728123ULL, 1442794654840575ULL}};
    const fe25519 sqrtADMinusOneScalar = {{
        2241493124984347ULL, 425987919032274ULL, 2207028919301688ULL,
        1220490630685848ULL, 974799131293748ULL}};
    const fe25519 invSqrtAMinusDScalar = {{
        278908739862762ULL, 821645201101625ULL, 8113234426968ULL,
        1777959178193151ULL, 2118520810568447ULL}};
    const fe25519 oneMinusDSquaredScalar = {{
        1136626929484150ULL, 1998550399581263ULL, 496427632559748ULL,
        118527312129759ULL, 45110755273534ULL}};
    const fe25519 dMinusOneSquaredScalar = {{
        1507062230895904ULL, 1572317787530805ULL, 683053064812840ULL,
        317374165784489ULL, 1572899562415810ULL}};

    void broadcast(gfe4x& out, const fe25519& value)
    {
        unsigned char one[32];
        unsigned char packed[4 * 32];
        fe25519_pack(one, &value);
        std::memcpy(packed + 0 * 32, one, 32);
        std::memcpy(packed + 1 * 32, one, 32);
        std::memcpy(packed + 2 * 32, one, 32);
        std::memcpy(packed + 3 * 32, one, 32);
        gfe4x_unpack(&out, packed);
    }

    struct RistrettoConstants
    {
        gfe4x sqrtM1;
        gfe4x d;
        gfe4x sqrtADMinusOne;
        gfe4x invSqrtAMinusD;
        gfe4x oneMinusDSquared;
        gfe4x dMinusOneSquared;
        gfe4x zero;
        gfe4x one;

        RistrettoConstants()
        {
            broadcast(sqrtM1, sqrtM1Scalar);
            broadcast(d, dScalar);
            broadcast(sqrtADMinusOne, sqrtADMinusOneScalar);
            broadcast(invSqrtAMinusD, invSqrtAMinusDScalar);
            broadcast(oneMinusDSquared, oneMinusDSquaredScalar);
            broadcast(dMinusOneSquared, dMinusOneSquaredScalar);
            gfe4x_setzero(&zero);
            gfe4x_setone(&one);
        }
    };

    const RistrettoConstants& constants()
    {
        static const RistrettoConstants value;
        return value;
    }

    void equal(unsigned char result[4], const gfe4x& x, const gfe4x& y)
    {
        gfe4x difference;
        unsigned char packed[4 * 32];
        gfe4x_sub(&difference, &x, &y);
        gfe4x_pack(packed, &difference);
        for (unsigned lane = 0; lane != 4; ++lane)
        {
            std::uint32_t different = 0;
            for (unsigned i = 0; i != 32; ++i)
                different |= packed[lane * 32 + i];
            result[lane] = static_cast<unsigned char>(1U ^
                ((different | (0U - different)) >> 31));
        }
    }

    void absolute(gfe4x& result, const gfe4x& value)
    {
        unsigned char negative[4];
        gfe4x negated;
        result = value;
        gfe4x_getparity(negative, &result);
        gfe4x_sub(&negated, &constants().zero, &result);
        gfe4x_cmov(&result, &negated, negative);
    }

    void sqrtRatioM1(
        unsigned char square[4], gfe4x& x, const gfe4x& u, const gfe4x& v)
    {
        const auto& c = constants();
        gfe4x v3, vxx, mcheck, pcheck, fcheck, xsqrtm1, t;
        unsigned char hasM[4], hasP[4], hasF[4], select[4];

        gfe4x_square(&v3, &v);
        gfe4x_mul(&v3, &v3, &v);
        gfe4x_square(&x, &v3);
        gfe4x_mul(&x, &x, &u);
        gfe4x_mul(&x, &x, &v);
        gfe4x_pow2523(&x, &x);
        gfe4x_mul(&x, &x, &v3);
        gfe4x_mul(&x, &x, &u);

        gfe4x_square(&vxx, &x);
        gfe4x_mul(&vxx, &vxx, &v);
        gfe4x_sub(&mcheck, &vxx, &u);
        gfe4x_add(&pcheck, &vxx, &u);
        gfe4x_mul(&t, &u, &c.sqrtM1);
        gfe4x_add(&fcheck, &vxx, &t);
        equal(hasM, mcheck, c.zero);
        equal(hasP, pcheck, c.zero);
        equal(hasF, fcheck, c.zero);
        gfe4x_mul(&xsqrtm1, &x, &c.sqrtM1);
        for (unsigned lane = 0; lane != 4; ++lane)
        {
            select[lane] = static_cast<unsigned char>(hasP[lane] | hasF[lane]);
            square[lane] = static_cast<unsigned char>(hasM[lane] | hasP[lane]);
        }
        gfe4x_cmov(&x, &xsqrtm1, select);
        absolute(x, x);
    }

    void ristrettoElligator(ge4x& p, const gfe4x& t)
    {
        const auto& k = constants();
        gfe4x c, n, r, rpd, s, sprime, ss, u, v, w0, w1, w2, w3;
        unsigned char square[4], nonsquare[4];

        gfe4x_square(&r, &t);
        gfe4x_mul(&r, &k.sqrtM1, &r);
        gfe4x_add(&u, &r, &k.one);
        gfe4x_mul(&u, &u, &k.oneMinusDSquared);
        gfe4x_sub(&c, &k.zero, &k.one);
        gfe4x_add(&rpd, &r, &k.d);
        gfe4x_mul(&v, &r, &k.d);
        gfe4x_sub(&v, &c, &v);
        gfe4x_mul(&v, &v, &rpd);
        sqrtRatioM1(square, s, u, v);
        for (unsigned lane = 0; lane != 4; ++lane)
            nonsquare[lane] = static_cast<unsigned char>(1U ^ square[lane]);
        gfe4x_mul(&sprime, &s, &t);
        absolute(sprime, sprime);
        gfe4x_sub(&sprime, &k.zero, &sprime);
        gfe4x_cmov(&s, &sprime, nonsquare);
        gfe4x_cmov(&c, &r, nonsquare);
        gfe4x_sub(&n, &r, &k.one);
        gfe4x_mul(&n, &n, &c);
        gfe4x_mul(&n, &n, &k.dMinusOneSquared);
        gfe4x_sub(&n, &n, &v);
        gfe4x_add(&w0, &s, &s);
        gfe4x_mul(&w0, &w0, &v);
        gfe4x_mul(&w1, &n, &k.sqrtADMinusOne);
        gfe4x_square(&ss, &s);
        gfe4x_sub(&w2, &k.one, &ss);
        gfe4x_add(&w3, &k.one, &ss);
        gfe4x_mul(&p.x, &w0, &w3);
        gfe4x_mul(&p.y, &w2, &w1);
        gfe4x_mul(&p.z, &w1, &w3);
        gfe4x_mul(&p.t, &w0, &w2);
    }

    bool encodingIsCanonical(const unsigned char s[32])
    {
        if ((s[31] & 0x80) != 0 || (s[0] & 1) != 0)
            return false;
        if ((s[31] & 0x7f) != 0x7f)
            return true;
        for (int i = 30; i != 0; --i)
            if (s[i] != 0xff)
                return true;
        return s[0] < 0xed;
    }
}

extern "C" void ge4x_ristretto_from_uniform(
    ge4x* r, const unsigned char uniform[4 * 64])
{
    unsigned char first[4 * 32];
    unsigned char second[4 * 32];
    for (unsigned lane = 0; lane != 4; ++lane)
    {
        std::memcpy(first + lane * 32, uniform + lane * 64, 32);
        std::memcpy(second + lane * 32, uniform + lane * 64 + 32, 32);
    }
    gfe4x t0, t1;
    ge4x p0, p1;
    gfe4x_unpack(&t0, first);
    gfe4x_unpack(&t1, second);
    ristrettoElligator(p0, t0);
    ristrettoElligator(p1, t1);
    ge4x_add(r, &p0, &p1);
}

extern "C" int ge4x_ristretto_frombytes(
    ge4x* h, const unsigned char encoded[4 * 32])
{
    const auto& c = constants();
    gfe4x s, ss, u1, u2, u1sq, u2sq, v, vu2sq, invsqrt;
    unsigned char valid[4], square[4], parity[4], zero[4];

    for (unsigned lane = 0; lane != 4; ++lane)
        valid[lane] = static_cast<unsigned char>(
            encodingIsCanonical(encoded + lane * 32));
    gfe4x_unpack(&s, encoded);
    gfe4x_square(&ss, &s);
    gfe4x_sub(&u1, &c.one, &ss);
    gfe4x_square(&u1sq, &u1);
    gfe4x_add(&u2, &c.one, &ss);
    gfe4x_square(&u2sq, &u2);
    gfe4x_mul(&v, &c.d, &u1sq);
    gfe4x_sub(&v, &c.zero, &v);
    gfe4x_sub(&v, &v, &u2sq);
    gfe4x_mul(&vu2sq, &v, &u2sq);
    sqrtRatioM1(square, invsqrt, c.one, vu2sq);
    gfe4x_mul(&h->x, &invsqrt, &u2);
    gfe4x_mul(&h->y, &invsqrt, &h->x);
    gfe4x_mul(&h->y, &h->y, &v);
    gfe4x_mul(&h->x, &h->x, &s);
    gfe4x_add(&h->x, &h->x, &h->x);
    absolute(h->x, h->x);
    gfe4x_mul(&h->y, &u1, &h->y);
    h->z = c.one;
    gfe4x_mul(&h->t, &h->x, &h->y);
    gfe4x_getparity(parity, &h->t);
    equal(zero, h->y, c.zero);

    unsigned allValid = 1;
    for (unsigned lane = 0; lane != 4; ++lane)
    {
        valid[lane] = static_cast<unsigned char>(valid[lane] & square[lane] &
            (1U ^ parity[lane]) & (1U ^ zero[lane]));
        allValid &= valid[lane];
    }
    return allValid ? 0 : -1;
}

extern "C" void ge4x_ristretto_tobytes(
    unsigned char encoded[4 * 32], const ge4x* h)
{
    const auto& c = constants();
    gfe4x den1, den2, deninv, eden, invsqrt, ix, iy, s, tzinv;
    gfe4x u1, u2, u1u2sq, x, y, xzinv, zinv, zmy, negy;
    unsigned char ignored[4], select[4];

    gfe4x_add(&u1, &h->z, &h->y);
    gfe4x_sub(&zmy, &h->z, &h->y);
    gfe4x_mul(&u1, &u1, &zmy);
    gfe4x_mul(&u2, &h->x, &h->y);
    gfe4x_square(&u1u2sq, &u2);
    gfe4x_mul(&u1u2sq, &u1, &u1u2sq);
    sqrtRatioM1(ignored, invsqrt, c.one, u1u2sq);
    gfe4x_mul(&den1, &invsqrt, &u1);
    gfe4x_mul(&den2, &invsqrt, &u2);
    gfe4x_mul(&zinv, &den1, &den2);
    gfe4x_mul(&zinv, &zinv, &h->t);
    gfe4x_mul(&ix, &h->x, &c.sqrtM1);
    gfe4x_mul(&iy, &h->y, &c.sqrtM1);
    gfe4x_mul(&eden, &den1, &c.invSqrtAMinusD);
    gfe4x_mul(&tzinv, &h->t, &zinv);
    gfe4x_getparity(select, &tzinv);
    x = h->x;
    y = h->y;
    deninv = den2;
    gfe4x_cmov(&x, &iy, select);
    gfe4x_cmov(&y, &ix, select);
    gfe4x_cmov(&deninv, &eden, select);
    gfe4x_mul(&xzinv, &x, &zinv);
    gfe4x_getparity(select, &xzinv);
    gfe4x_sub(&negy, &c.zero, &y);
    gfe4x_cmov(&y, &negy, select);
    gfe4x_sub(&s, &h->z, &y);
    gfe4x_mul(&s, &deninv, &s);
    absolute(s, s);
    gfe4x_pack(encoded, &s);
}
