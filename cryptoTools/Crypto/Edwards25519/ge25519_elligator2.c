#include "ge25519.h"

/* RFC 9380, Appendix G.2.1 and G.2.2. These constants use the same radix
 * 2^51 representation as the rest of this implementation. */
static const fe25519 ell2_c2 = {{
  1718705420411057ULL, 234908883556509ULL, 2233514472574048ULL,
  2117202627021982ULL, 765476049583133ULL}};
static const fe25519 ell2_sqrt_minus_one = {{
  1718705420411056ULL, 234908883556509ULL, 2233514472574048ULL,
  2117202627021982ULL, 765476049583133ULL}};
static const fe25519 edwards_sqrt_minus_486664 = {{
  1693982333959686ULL, 608509411481997ULL, 2235573344831311ULL,
  947681270984193ULL, 266558006233600ULL}};

static unsigned char fe_equal(const fe25519 *x, const fe25519 *y)
{
  fe25519 a = *x;
  fe25519 b = *y;
  unsigned long long different;
  fe25519_freeze(&a);
  fe25519_freeze(&b);
  different = (a.v[0] ^ b.v[0]) | (a.v[1] ^ b.v[1]) |
              (a.v[2] ^ b.v[2]) | (a.v[3] ^ b.v[3]) |
              (a.v[4] ^ b.v[4]);
  return (unsigned char)(1U ^
      (unsigned int)((different | (0ULL - different)) >> 63));
}

void ge25519_map_to_curve_elligator2(ge25519 *r, const fe25519 *u)
{
  fe25519 tv1, tv2, tv3, xd, x1n, gxd, gx1;
  fe25519 y11, y12, x2n, y21, y22, gx2, y1, y2, yneg;
  fe25519 j, zero, one;
  fe25519 xmn, ymn, xn, xdn, yn, yd;
  unsigned char e1, e2, e3, e4, exceptional;

  fe25519_setint(&j, 486662);
  fe25519_setint(&zero, 0);
  fe25519_setint(&one, 1);

  fe25519_square(&tv1, u);
  fe25519_add(&tv1, &tv1, &tv1);
  fe25519_add(&xd, &tv1, &one);
  fe25519_neg(&x1n, &j);
  fe25519_square(&tv2, &xd);
  fe25519_mul(&gxd, &tv2, &xd);
  fe25519_mul(&gx1, &j, &tv1);
  fe25519_mul(&gx1, &gx1, &x1n);
  fe25519_add(&gx1, &gx1, &tv2);
  fe25519_mul(&gx1, &gx1, &x1n);

  fe25519_square(&tv3, &gxd);
  fe25519_square(&tv2, &tv3);
  fe25519_mul(&tv3, &tv3, &gxd);
  fe25519_mul(&tv3, &tv3, &gx1);
  fe25519_mul(&tv2, &tv2, &tv3);
  fe25519_pow2523(&y11, &tv2);
  fe25519_mul(&y11, &y11, &tv3);
  fe25519_mul(&y12, &y11, &ell2_sqrt_minus_one);
  fe25519_square(&tv2, &y11);
  fe25519_mul(&tv2, &tv2, &gxd);
  e1 = fe_equal(&tv2, &gx1);
  y1 = y12;
  fe25519_cmov(&y1, &y11, e1);

  fe25519_mul(&x2n, &x1n, &tv1);
  fe25519_mul(&y21, &y11, u);
  fe25519_mul(&y21, &y21, &ell2_c2);
  fe25519_mul(&y22, &y21, &ell2_sqrt_minus_one);
  fe25519_mul(&gx2, &gx1, &tv1);
  fe25519_square(&tv2, &y21);
  fe25519_mul(&tv2, &tv2, &gxd);
  e2 = fe_equal(&tv2, &gx2);
  y2 = y22;
  fe25519_cmov(&y2, &y21, e2);

  fe25519_square(&tv2, &y1);
  fe25519_mul(&tv2, &tv2, &gxd);
  e3 = fe_equal(&tv2, &gx1);
  xmn = x2n;
  fe25519_cmov(&xmn, &x1n, e3);
  ymn = y2;
  fe25519_cmov(&ymn, &y1, e3);
  e4 = fe25519_getparity(&ymn);
  fe25519_neg(&yneg, &ymn);
  fe25519_cmov(&ymn, &yneg, (unsigned char)(e3 ^ e4));
  /* Rational map from curve25519 to edwards25519. */
  xn = xmn;
  fe25519_mul(&xn, &xn, &edwards_sqrt_minus_486664);
  fe25519_mul(&xdn, &xd, &ymn);
  fe25519_sub(&yn, &xmn, &xd);
  fe25519_add(&yd, &xmn, &xd);
  fe25519_mul(&tv1, &xdn, &yd);
  exceptional = fe_equal(&tv1, &zero);
  fe25519_cmov(&xn, &zero, exceptional);
  fe25519_cmov(&xdn, &one, exceptional);
  fe25519_cmov(&yn, &one, exceptional);
  fe25519_cmov(&yd, &one, exceptional);

  /* (xn/xd, yn/yd) -> extended projective coordinates. */
  fe25519_mul(&r->x, &xn, &yd);
  fe25519_mul(&r->y, &yn, &xdn);
  fe25519_mul(&r->z, &xdn, &yd);
  fe25519_mul(&r->t, &xn, &yn);
}
