#include "ge4x.h"

void ge4x_map_to_curve_elligator2(ge4x *r, const fe25519 u[4])
{
  ge25519_map_to_curve_elligator2(&r->lane[0], &u[0]);
  ge25519_map_to_curve_elligator2(&r->lane[1], &u[1]);
  ge25519_map_to_curve_elligator2(&r->lane[2], &u[2]);
  ge25519_map_to_curve_elligator2(&r->lane[3], &u[3]);
}
