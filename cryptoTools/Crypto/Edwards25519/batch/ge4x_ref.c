#include "ge4x.h"

#include <string.h>

static unsigned char ct_equal(unsigned char a, unsigned char b)
{
  unsigned int x = (unsigned int)(a ^ b);
  return (unsigned char)(((x | (0U - x)) >> 31) ^ 1U);
}

static void lookup_lane(ge25519 *r, ge4x const table[8], int lane,
                        const signed char *digit)
{
  const int d = (int)*digit;
  const unsigned int neg = (unsigned int)(d < 0);
  const unsigned char mag = (unsigned char)((d ^ -(int)neg) + (int)neg);
  ge25519 n;
  unsigned char i;
  ge25519_setneutral(r);
  for (i = 1; i <= 8; ++i)
    ge25519_cmov(r, &table[i - 1].lane[lane], ct_equal(mag, i));
  ge25519_neg(&n, r);
  ge25519_cmov(r, &n, (unsigned char)neg);
}

void ge4x_from_ge25519(ge4x *r, const ge25519 *p)
{
  int i;
  for (i = 0; i != 4; ++i)
    r->lane[i] = *p;
}

void ge4x_from_ge25519s(ge4x *r, const ge25519 p[4])
{
  int i;
  for (i = 0; i != 4; ++i)
    r->lane[i] = p[i];
}

void ge4x_to_ge25519s(ge25519 p[4], const ge4x *r)
{
  int i;
  for (i = 0; i != 4; ++i)
    p[i] = r->lane[i];
}

void ge4x_cmovs(ge4x *r, const ge4x *x, unsigned char *b)
{
  int i;
  for (i = 0; i != 4; ++i) {
    ge25519 t = x->lane[i];
    ge25519_cmov(&r->lane[i], &t, b[i]);
  }
}

void ge4x_setneutral(ge4x *r)
{
  int i;
  for (i = 0; i != 4; ++i)
    ge25519_setneutral(&r->lane[i]);
}

void ge4x_neg(ge4x *r, const ge4x *p)
{
  int i;
  for (i = 0; i != 4; ++i)
    ge25519_neg(&r->lane[i], &p->lane[i]);
}

void ge4x_add(ge4x *r, const ge4x *p, const ge4x *q)
{
  int i;
  for (i = 0; i != 4; ++i)
    ge25519_add(&r->lane[i], &p->lane[i], &q->lane[i]);
}

void ge4x_sub(ge4x *r, const ge4x *p, const ge4x *q)
{
  int i;
  for (i = 0; i != 4; ++i)
    ge25519_subtract(&r->lane[i], &p->lane[i], &q->lane[i]);
}

void ge4x_double(ge4x *r, const ge4x *p)
{
  int i;
  for (i = 0; i != 4; ++i)
    ge25519_double(&r->lane[i], &p->lane[i]);
}

void ge4x_maketable(ge4x (*table)[8], const ge4x *p, int dist)
{
  const int n = 64 / dist;
  ge4x q = *p;
  int i, j;
  for (i = 0; i != n; ++i) {
    table[i][0] = q;
    ge4x_double(&table[i][1], &q);
    ge4x_add(&table[i][2], &table[i][1], &q);
    ge4x_double(&table[i][3], &table[i][1]);
    ge4x_add(&table[i][4], &table[i][3], &q);
    ge4x_double(&table[i][5], &table[i][2]);
    ge4x_add(&table[i][6], &table[i][5], &q);
    ge4x_double(&table[i][7], &table[i][3]);
    if (i + 1 != n) {
      ge4x_double(&q, &table[i][7]);
      for (j = 0; j != 4 * (dist - 1); ++j)
        ge4x_double(&q, &q);
    }
  }
}

void ge4x_scalarsmults_base(ge4x *r, const sc25519 *s)
{
  int i;
  for (i = 0; i != 4; ++i)
    ge25519_scalarmult_base(&r->lane[i], &s[i]);
}

void ge4x_scalarmults_base(ge4x *r, const sc25519 *s)
{
  sc25519 ss[4];
  int i;
  for (i = 0; i != 4; ++i)
    ss[i] = *s;
  ge4x_scalarsmults_base(r, ss);
}

void ge4x_scalarsmults(ge4x *r, ge4x *p, const sc25519 *s)
{
  int i;
  for (i = 0; i != 4; ++i)
    ge25519_scalarmult(&r->lane[i], &p->lane[i], &s[i]);
}

void ge4x_scalarmults(ge4x *r, ge4x *p, const sc25519 *s)
{
  sc25519 ss[4];
  int i;
  for (i = 0; i != 4; ++i)
    ss[i] = *s;
  ge4x_scalarsmults(r, p, ss);
}

void ge4x_scalarsmults_table(ge4x *r, const ge4x (*table)[8],
                             const sc25519 *s, int dist)
{
  int lane;
  for (lane = 0; lane != 4; ++lane) {
    signed char w[64];
    ge25519 acc, t;
    int i, j;
    int first = 1;
    sc25519_window4(w, &s[lane]);

    for (i = dist - 1; i < 64; i += dist) {
      lookup_lane(&t, table[i / dist], lane, &w[i]);
      if (first) {
        acc = t;
        first = 0;
      } else {
        ge25519_add(&acc, &acc, &t);
      }
    }

    for (i = dist - 2; i >= 0; --i) {
      int k;
      for (k = 0; k != 4; ++k)
        ge25519_double(&acc, &acc);
      for (j = i; j < 64; j += dist) {
        lookup_lane(&t, table[j / dist], lane, &w[j]);
        ge25519_add(&acc, &acc, &t);
      }
    }
    r->lane[lane] = acc;
  }
}

int ge4x_unpack_vartime(ge4x *r, unsigned char p[128])
{
  int i;
  for (i = 0; i != 4; ++i)
    if (ge25519_unpack_vartime(&r->lane[i], p + 32 * i) != 0)
      return -1;
  return 0;
}

void ge4x_pack(unsigned char r[128], const ge4x *p)
{
  int i;
  for (i = 0; i != 4; ++i)
    ge25519_pack(r + 32 * i, &p->lane[i]);
}
