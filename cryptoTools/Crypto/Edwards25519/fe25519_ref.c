#include "fe25519.h"

#include <stdint.h>

/* Portable radix-2^51 field arithmetic.  This deliberately avoids compiler
 * extensions such as __int128 so the reference backend also builds with
 * MSVC. */
typedef struct {
  uint64_t lo;
  uint64_t hi;
} uint128_ref;

static uint128_ref mul64(uint64_t a, uint64_t b)
{
  const uint64_t a0 = (uint32_t)a;
  const uint64_t a1 = a >> 32;
  const uint64_t b0 = (uint32_t)b;
  const uint64_t b1 = b >> 32;
  const uint64_t p00 = a0 * b0;
  const uint64_t p01 = a0 * b1;
  const uint64_t p10 = a1 * b0;
  const uint64_t p11 = a1 * b1;
  const uint64_t middle = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;
  uint128_ref r;
  r.lo = (middle << 32) | (uint32_t)p00;
  r.hi = p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32);
  return r;
}

static void add128(uint128_ref *r, uint128_ref a)
{
  const uint64_t old = r->lo;
  r->lo += a.lo;
  r->hi += a.hi + (r->lo < old);
}

static void add_product(uint128_ref *r, uint64_t a, uint64_t b)
{
  add128(r, mul64(a, b));
}

static uint64_t shr51(uint128_ref a)
{
  return (a.lo >> 51) | (a.hi << 13);
}

void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y)
{
  const uint64_t x0 = x->v[0], x1 = x->v[1], x2 = x->v[2];
  const uint64_t x3 = x->v[3], x4 = x->v[4];
  const uint64_t y0 = y->v[0], y1 = y->v[1], y2 = y->v[2];
  const uint64_t y3 = y->v[3], y4 = y->v[4];
  uint128_ref h0 = {0, 0}, h1 = {0, 0}, h2 = {0, 0};
  uint128_ref h3 = {0, 0}, h4 = {0, 0};
  uint64_t c;
  const uint64_t mask = UINT64_C(0x7ffffffffffff);

  add_product(&h0, x0, y0);
  add_product(&h0, 19 * x1, y4);
  add_product(&h0, 19 * x2, y3);
  add_product(&h0, 19 * x3, y2);
  add_product(&h0, 19 * x4, y1);

  add_product(&h1, x0, y1);
  add_product(&h1, x1, y0);
  add_product(&h1, 19 * x2, y4);
  add_product(&h1, 19 * x3, y3);
  add_product(&h1, 19 * x4, y2);

  add_product(&h2, x0, y2);
  add_product(&h2, x1, y1);
  add_product(&h2, x2, y0);
  add_product(&h2, 19 * x3, y4);
  add_product(&h2, 19 * x4, y3);

  add_product(&h3, x0, y3);
  add_product(&h3, x1, y2);
  add_product(&h3, x2, y1);
  add_product(&h3, x3, y0);
  add_product(&h3, 19 * x4, y4);

  add_product(&h4, x0, y4);
  add_product(&h4, x1, y3);
  add_product(&h4, x2, y2);
  add_product(&h4, x3, y1);
  add_product(&h4, x4, y0);

  c = shr51(h0); h0.lo &= mask; add128(&h1, (uint128_ref){c, 0});
  c = shr51(h1); h1.lo &= mask; add128(&h2, (uint128_ref){c, 0});
  c = shr51(h2); h2.lo &= mask; add128(&h3, (uint128_ref){c, 0});
  c = shr51(h3); h3.lo &= mask; add128(&h4, (uint128_ref){c, 0});
  c = shr51(h4); h4.lo &= mask;
  h0.lo += 19 * c;
  c = h0.lo >> 51; h0.lo &= mask; h1.lo += c;

  r->v[0] = h0.lo;
  r->v[1] = h1.lo;
  r->v[2] = h2.lo;
  r->v[3] = h3.lo;
  r->v[4] = h4.lo;
}

void fe25519_square(fe25519 *r, const fe25519 *x)
{
  fe25519_mul(r, x, x);
}

void fe25519_nsquare(fe25519 *r, unsigned long long n)
{
  while (n--)
    fe25519_square(r, r);
}

void fe25519_freeze(fe25519 *r)
{
  const uint64_t mask51 = UINT64_C(0x7ffffffffffff);
  const uint64_t base = UINT64_C(0x8000000000000);
  uint64_t t[5], borrow, select;
  int round, i;

  for (round = 0; round != 3; ++round) {
    uint64_t c;
    for (i = 0; i != 4; ++i) {
      c = r->v[i] >> 51;
      r->v[i] &= mask51;
      r->v[i + 1] += c;
    }
    c = r->v[4] >> 51;
    r->v[4] &= mask51;
    r->v[0] += 19 * c;
  }

  t[0] = r->v[0] + base - (base - 19);
  borrow = 1 - (t[0] >> 51);
  t[0] &= mask51;
  for (i = 1; i != 5; ++i) {
    t[i] = r->v[i] + base - mask51 - borrow;
    borrow = 1 - (t[i] >> 51);
    t[i] &= mask51;
  }

  select = (uint64_t)0 - (uint64_t)(1 - borrow);
  for (i = 0; i != 5; ++i)
    r->v[i] ^= select & (r->v[i] ^ t[i]);
}
