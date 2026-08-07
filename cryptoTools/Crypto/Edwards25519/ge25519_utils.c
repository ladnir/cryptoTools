#include "ge25519.h"

void ge25519_cmov(ge25519 *r, const ge25519 *s, unsigned char b)
{
  fe25519_cmov(&r->x, &s->x, b);
  fe25519_cmov(&r->y, &s->y, b);
  fe25519_cmov(&r->z, &s->z, b);
  fe25519_cmov(&r->t, &s->t, b);
}

void ge25519_neg(ge25519 *r, const ge25519 *s)
{
  ge25519 t = *s;
  fe25519_neg(&t.x, &t.x);
  fe25519_neg(&t.t, &t.t);
  *r = t;
}

int ge25519_isneutral_vartime(const ge25519 *p)
{
  return fe25519_iszero_vartime(&p->x) && fe25519_iseq_vartime(&p->y, &p->z);
}

void ge25519_subtract(ge25519 *r, const ge25519 *p, const ge25519 *q)
{
  ge25519 n;
  ge25519_neg(&n, q);
  ge25519_add(r, p, &n);
}
