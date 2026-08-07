#include "sc25519.h"

#include <string.h>

void sc25519_to32bytes(unsigned char r[32], const sc25519 *x)
{
  /* sc25519_from32bytes stores four little-endian 64-bit words. */
  unsigned long long words[4];
  int i, j;
  memcpy(words, x->v, sizeof(words));
  for (i = 0; i != 4; ++i)
    for (j = 0; j != 8; ++j)
      r[8 * i + j] = (unsigned char)(words[i] >> (8 * j));
}
