#include "fe25519.h"

#include <stdint.h>

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b)
{
  const uint64_t mask = (uint64_t)0 - (uint64_t)(b != 0);
  int i;
  for (i = 0; i != 5; ++i)
    r->v[i] ^= mask & (r->v[i] ^ x->v[i]);
}

void fe25519_cswap(fe25519 *r, fe25519 *x, unsigned char b)
{
  const uint64_t mask = (uint64_t)0 - (uint64_t)(b != 0);
  int i;
  for (i = 0; i != 5; ++i) {
    const uint64_t t = mask & (r->v[i] ^ x->v[i]);
    r->v[i] ^= t;
    x->v[i] ^= t;
  }
}

int fe25519_iszero_vartime(const fe25519 *x)
{
  fe25519 t = *x;
  fe25519_freeze(&t);
  return (t.v[0] | t.v[1] | t.v[2] | t.v[3] | t.v[4]) == 0;
}

void fe25519_mul121666(fe25519 *r, const fe25519 *x)
{
  fe25519 c;
  fe25519_setint(&c, 121666);
  fe25519_mul(r, x, &c);
}
