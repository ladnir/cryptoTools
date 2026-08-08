/* SPDX-License-Identifier: ISC
 *
 * Ristretto255 formulas adapted from libsodium's ref10 implementation.
 * Copyright (c) 2013-2026 Frank Denis <j at pureftpd dot org>.
 * Field and group arithmetic use cryptoTools' Edwards25519 backend. See
 * RISTRETTO_LICENSE for the full ISC license notice.
 */
#include "ristretto255_ref.h"

#include <stdint.h>

static const fe25519 sqrtm1 = {{
  1718705420411056ULL, 234908883556509ULL, 2233514472574048ULL,
  2117202627021982ULL, 765476049583133ULL}};
static const fe25519 d = {{
  929955233495203ULL, 466365720129213ULL, 1662059464998953ULL,
  2033849074728123ULL, 1442794654840575ULL}};
static const fe25519 sqrtadm1 = {{
  2241493124984347ULL, 425987919032274ULL, 2207028919301688ULL,
  1220490630685848ULL, 974799131293748ULL}};
static const fe25519 invsqrtamd = {{
  278908739862762ULL, 821645201101625ULL, 8113234426968ULL,
  1777959178193151ULL, 2118520810568447ULL}};
static const fe25519 onemsqd = {{
  1136626929484150ULL, 1998550399581263ULL, 496427632559748ULL,
  118527312129759ULL, 45110755273534ULL}};
static const fe25519 sqdmone = {{
  1507062230895904ULL, 1572317787530805ULL, 683053064812840ULL,
  317374165784489ULL, 1572899562415810ULL}};

static unsigned char fe_negative(const fe25519 *x)
{
  return fe25519_getparity(x);
}

static void fe_abs(fe25519 *r, const fe25519 *x)
{
  fe25519 n;
  *r = *x;
  fe25519_neg(&n, x);
  fe25519_cmov(r, &n, fe_negative(r));
}

/* Return one exactly when u/v is square, and set x to the nonnegative square
 * root of u/v or sqrt(i*u/v), as required by the Ristretto formulas. */
static int sqrt_ratio_m1(fe25519 *x, const fe25519 *u, const fe25519 *v)
{
  fe25519 v3, vxx, mcheck, pcheck, fcheck, xsqrtm1;
  int has_m, has_p, has_f;

  fe25519_square(&v3, v);
  fe25519_mul(&v3, &v3, v);
  fe25519_square(x, &v3);
  fe25519_mul(x, x, u);
  fe25519_mul(x, x, v);
  fe25519_pow2523(x, x);
  fe25519_mul(x, x, &v3);
  fe25519_mul(x, x, u);

  fe25519_square(&vxx, x);
  fe25519_mul(&vxx, &vxx, v);
  fe25519_sub(&mcheck, &vxx, u);
  fe25519_add(&pcheck, &vxx, u);
  fe25519_mul(&fcheck, u, &sqrtm1);
  fe25519_add(&fcheck, &vxx, &fcheck);
  has_m = fe25519_iszero_vartime(&mcheck);
  has_p = fe25519_iszero_vartime(&pcheck);
  has_f = fe25519_iszero_vartime(&fcheck);
  fe25519_mul(&xsqrtm1, x, &sqrtm1);
  fe25519_cmov(x, &xsqrtm1, (unsigned char)(has_p | has_f));
  fe_abs(x, x);
  return has_m | has_p;
}

static int encoding_is_canonical(const unsigned char s[32])
{
  int i;
  if ((s[31] & 0x80) != 0 || (s[0] & 1) != 0)
    return 0;
  if ((s[31] & 0x7f) != 0x7f)
    return 1;
  for (i = 30; i != 0; --i)
    if (s[i] != 0xff)
      return 1;
  return s[0] < 0xed;
}

int osuCrypto_ristretto255_frombytes(ge25519 *h, const unsigned char s[32])
{
  fe25519 invsqrt, one, sf, ss, u1, u2, u1sq, u2sq, v, vu2sq;
  int square;

  if (!encoding_is_canonical(s))
    return -1;
  fe25519_unpack(&sf, s);
  fe25519_square(&ss, &sf);
  fe25519_setint(&one, 1);
  fe25519_sub(&u1, &one, &ss);
  fe25519_square(&u1sq, &u1);
  fe25519_add(&u2, &one, &ss);
  fe25519_square(&u2sq, &u2);
  fe25519_mul(&v, &d, &u1sq);
  fe25519_neg(&v, &v);
  fe25519_sub(&v, &v, &u2sq);
  fe25519_mul(&vu2sq, &v, &u2sq);

  square = sqrt_ratio_m1(&invsqrt, &one, &vu2sq);
  fe25519_mul(&h->x, &invsqrt, &u2);
  fe25519_mul(&h->y, &invsqrt, &h->x);
  fe25519_mul(&h->y, &h->y, &v);
  fe25519_mul(&h->x, &h->x, &sf);
  fe25519_add(&h->x, &h->x, &h->x);
  fe_abs(&h->x, &h->x);
  fe25519_mul(&h->y, &u1, &h->y);
  fe25519_setint(&h->z, 1);
  fe25519_mul(&h->t, &h->x, &h->y);

  return (!square || fe_negative(&h->t) || fe25519_iszero_vartime(&h->y)) ? -1 : 0;
}

void osuCrypto_ristretto255_tobytes(unsigned char s[32], const ge25519 *h)
{
  fe25519 den1, den2, deninv, eden, invsqrt, ix, iy, one, sf;
  fe25519 tzinv, u1, u2, u1u2sq, x, y, xzinv, zinv, zmy;
  unsigned char rotate;

  fe25519_add(&u1, &h->z, &h->y);
  fe25519_sub(&zmy, &h->z, &h->y);
  fe25519_mul(&u1, &u1, &zmy);
  fe25519_mul(&u2, &h->x, &h->y);
  fe25519_square(&u1u2sq, &u2);
  fe25519_mul(&u1u2sq, &u1, &u1u2sq);
  fe25519_setint(&one, 1);
  (void)sqrt_ratio_m1(&invsqrt, &one, &u1u2sq);
  fe25519_mul(&den1, &invsqrt, &u1);
  fe25519_mul(&den2, &invsqrt, &u2);
  fe25519_mul(&zinv, &den1, &den2);
  fe25519_mul(&zinv, &zinv, &h->t);
  fe25519_mul(&ix, &h->x, &sqrtm1);
  fe25519_mul(&iy, &h->y, &sqrtm1);
  fe25519_mul(&eden, &den1, &invsqrtamd);
  fe25519_mul(&tzinv, &h->t, &zinv);
  rotate = fe_negative(&tzinv);
  x = h->x;
  y = h->y;
  deninv = den2;
  fe25519_cmov(&x, &iy, rotate);
  fe25519_cmov(&y, &ix, rotate);
  fe25519_cmov(&deninv, &eden, rotate);
  fe25519_mul(&xzinv, &x, &zinv);
  {
    fe25519 negy;
    fe25519_neg(&negy, &y);
    fe25519_cmov(&y, &negy, fe_negative(&xzinv));
  }
  fe25519_sub(&sf, &h->z, &y);
  fe25519_mul(&sf, &deninv, &sf);
  fe_abs(&sf, &sf);
  fe25519_pack(s, &sf);
}

static void elligator(ge25519 *p, const fe25519 *t)
{
  fe25519 c, n, one, r, rpd, s, sprime, ss, u, v, w0, w1, w2, w3;
  unsigned char nonsquare;

  fe25519_setint(&one, 1);
  fe25519_square(&r, t);
  fe25519_mul(&r, &sqrtm1, &r);
  fe25519_add(&u, &r, &one);
  fe25519_mul(&u, &u, &onemsqd);
  fe25519_neg(&c, &one);
  fe25519_add(&rpd, &r, &d);
  fe25519_mul(&v, &r, &d);
  fe25519_sub(&v, &c, &v);
  fe25519_mul(&v, &v, &rpd);
  nonsquare = (unsigned char)(1 - sqrt_ratio_m1(&s, &u, &v));
  fe25519_mul(&sprime, &s, t);
  fe_abs(&sprime, &sprime);
  fe25519_neg(&sprime, &sprime);
  fe25519_cmov(&s, &sprime, nonsquare);
  fe25519_cmov(&c, &r, nonsquare);
  fe25519_sub(&n, &r, &one);
  fe25519_mul(&n, &n, &c);
  fe25519_mul(&n, &n, &sqdmone);
  fe25519_sub(&n, &n, &v);
  fe25519_add(&w0, &s, &s);
  fe25519_mul(&w0, &w0, &v);
  fe25519_mul(&w1, &n, &sqrtadm1);
  fe25519_square(&ss, &s);
  fe25519_sub(&w2, &one, &ss);
  fe25519_add(&w3, &one, &ss);
  fe25519_mul(&p->x, &w0, &w3);
  fe25519_mul(&p->y, &w2, &w1);
  fe25519_mul(&p->z, &w1, &w3);
  fe25519_mul(&p->t, &w0, &w2);
}

void osuCrypto_ristretto255_from_uniform(ge25519 *r, const unsigned char uniform[64])
{
  fe25519 t0, t1;
  ge25519 p0, p1;
  fe25519_unpack(&t0, uniform);
  fe25519_unpack(&t1, uniform + 32);
  elligator(&p0, &t0);
  elligator(&p1, &t1);
  ge25519_add(r, &p0, &p1);
}
