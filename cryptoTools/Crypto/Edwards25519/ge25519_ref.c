#include "ge25519.h"

#include <stdint.h>

static const fe25519 ec2d = {{1859910466990425ULL, 932731440258426ULL,
  1072319116312658ULL, 1815898335770999ULL, 633789495995903ULL}};

static unsigned char ct_equal(unsigned char a, unsigned char b)
{
  uint32_t x = (uint32_t)(a ^ b);
  return (unsigned char)(((x | (0U - x)) >> 31) ^ 1U);
}

static void niels_setneutral(ge25519_niels *r)
{
  fe25519_setint(&r->ysubx, 1);
  fe25519_setint(&r->xaddy, 1);
  fe25519_setint(&r->t2d, 0);
}

static void niels_cmov(ge25519_niels *r, const ge25519_niels *x, unsigned char b)
{
  fe25519_cmov(&r->ysubx, &x->ysubx, b);
  fe25519_cmov(&r->xaddy, &x->xaddy, b);
  fe25519_cmov(&r->t2d, &x->t2d, b);
}

void ge25519_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p)
{
  fe25519_mul(&r->x, &p->x, &p->t);
  fe25519_mul(&r->y, &p->y, &p->z);
  fe25519_mul(&r->z, &p->z, &p->t);
}

void ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p)
{
  fe25519_mul(&r->x, &p->x, &p->t);
  fe25519_mul(&r->y, &p->y, &p->z);
  fe25519_mul(&r->z, &p->z, &p->t);
  fe25519_mul(&r->t, &p->x, &p->y);
}

void ge25519_p1p1_to_pniels(ge25519_pniels *r, const ge25519_p1p1 *p)
{
  ge25519 q;
  ge25519_p1p1_to_p3(&q, p);
  fe25519_sub(&r->ysubx, &q.y, &q.x);
  fe25519_add(&r->xaddy, &q.y, &q.x);
  fe25519_add(&r->z, &q.z, &q.z);
  fe25519_mul(&r->t2d, &q.t, &ec2d);
}

void ge25519_add_p1p1(ge25519_p1p1 *r, const ge25519_p3 *p,
                      const ge25519_p3 *q)
{
  fe25519 a, b, c, d, t;
  fe25519_sub(&a, &p->y, &p->x);
  fe25519_sub(&t, &q->y, &q->x);
  fe25519_mul(&a, &a, &t);
  fe25519_add(&b, &p->x, &p->y);
  fe25519_add(&t, &q->x, &q->y);
  fe25519_mul(&b, &b, &t);
  fe25519_mul(&c, &p->t, &q->t);
  fe25519_mul(&c, &c, &ec2d);
  fe25519_mul(&d, &p->z, &q->z);
  fe25519_add(&d, &d, &d);
  fe25519_sub(&r->x, &b, &a);
  fe25519_sub(&r->t, &d, &c);
  fe25519_add(&r->z, &d, &c);
  fe25519_add(&r->y, &b, &a);
}

void ge25519_dbl_p1p1(ge25519_p1p1 *r, const ge25519_p2 *p)
{
  fe25519 a, b, c, d;
  fe25519_square(&a, &p->x);
  fe25519_square(&b, &p->y);
  fe25519_square(&c, &p->z);
  fe25519_add(&c, &c, &c);
  fe25519_neg(&d, &a);
  fe25519_add(&r->x, &p->x, &p->y);
  fe25519_square(&r->x, &r->x);
  fe25519_sub(&r->x, &r->x, &a);
  fe25519_sub(&r->x, &r->x, &b);
  fe25519_add(&r->z, &d, &b);
  fe25519_sub(&r->t, &r->z, &c);
  fe25519_sub(&r->y, &d, &b);
}

void ge25519_nielsadd_p1p1(ge25519_p1p1 *r, const ge25519_p3 *p,
                           const ge25519_niels *q)
{
  fe25519 a, b, c, d;
  fe25519_sub(&a, &p->y, &p->x);
  fe25519_mul(&a, &a, &q->ysubx);
  fe25519_add(&b, &p->y, &p->x);
  fe25519_mul(&b, &b, &q->xaddy);
  fe25519_mul(&c, &p->t, &q->t2d);
  fe25519_add(&d, &p->z, &p->z);
  fe25519_sub(&r->x, &b, &a);
  fe25519_add(&r->y, &b, &a);
  fe25519_add(&r->z, &d, &c);
  fe25519_sub(&r->t, &d, &c);
}

void ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519_p3 *p,
                            const ge25519_pniels *q)
{
  fe25519 a, b, c, d;
  fe25519_sub(&a, &p->y, &p->x);
  fe25519_mul(&a, &a, &q->ysubx);
  fe25519_add(&b, &p->y, &p->x);
  fe25519_mul(&b, &b, &q->xaddy);
  fe25519_mul(&c, &p->t, &q->t2d);
  fe25519_mul(&d, &p->z, &q->z);
  fe25519_add(&d, &d, &d);
  fe25519_sub(&r->x, &b, &a);
  fe25519_add(&r->y, &b, &a);
  fe25519_add(&r->z, &d, &c);
  fe25519_sub(&r->t, &d, &c);
}

void ge25519_nielsadd2(ge25519_p3 *r, const ge25519_niels *q)
{
  ge25519_p1p1 t;
  ge25519_nielsadd_p1p1(&t, r, q);
  ge25519_p1p1_to_p3(r, &t);
}

void ge25519_lookup_asm(ge25519 *r, const ge25519 *table, const signed char *digit)
{
  const int d = (int)*digit;
  const unsigned int neg = (unsigned int)(d < 0);
  const unsigned char mag = (unsigned char)((d ^ -(int)neg) + (int)neg);
  ge25519 negated;
  unsigned char i;
  ge25519_setneutral(r);
  for (i = 1; i <= 8; ++i)
    ge25519_cmov(r, &table[i - 1], ct_equal(mag, i));
  ge25519_neg(&negated, r);
  ge25519_cmov(r, &negated, (unsigned char)neg);
}

void ge25519_lookup_niels_asm(ge25519_niels *r,
                              const ge25519_niels *table,
                              const signed char *digit)
{
  const int d = (int)*digit;
  const unsigned int neg = (unsigned int)(d < 0);
  const unsigned char mag = (unsigned char)((d ^ -(int)neg) + (int)neg);
  ge25519_niels n;
  unsigned char i;
  niels_setneutral(r);
  for (i = 1; i <= 8; ++i)
    niels_cmov(r, &table[i - 1], ct_equal(mag, i));
  n.ysubx = r->xaddy;
  n.xaddy = r->ysubx;
  fe25519_neg(&n.t2d, &r->t2d);
  niels_cmov(r, &n, (unsigned char)neg);
}
