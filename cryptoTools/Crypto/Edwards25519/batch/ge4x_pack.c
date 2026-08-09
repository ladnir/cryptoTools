#include "ge4x.h"

static void ge4x_pack_with_inverse(
  unsigned char r[128], const ge4x *p, const gfe4x *zi)
{
  gfe4x tx, ty;
  gfe4x_mul(&tx, &p->x, zi);
  gfe4x_mul(&ty, &p->y, zi);
  gfe4x_pack(r, &ty);

  unsigned char res[4];
  gfe4x_getparity(res, &tx);

  r[31] ^= res[0] << 7;
  r[63] ^= res[1] << 7;
  r[95] ^= res[2] << 7;
  r[127] ^= res[3] << 7;
}

void ge4x_pack(unsigned char r[128], const ge4x *p)
{
  gfe4x zi;
  gfe4x_invert(&zi, &p->z);
  ge4x_pack_with_inverse(r, p, &zi);
}

void ge4x_pack2(unsigned char r[256], const ge4x p[2])
{
  gfe4x product, inverse, zi0, zi1;
  gfe4x_mul(&product, &p[0].z, &p[1].z);
  gfe4x_invert(&inverse, &product);
  gfe4x_mul(&zi0, &inverse, &p[1].z);
  gfe4x_mul(&zi1, &inverse, &p[0].z);
  ge4x_pack_with_inverse(r, &p[0], &zi0);
  ge4x_pack_with_inverse(r + 128, &p[1], &zi1);
}

