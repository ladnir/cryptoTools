#ifndef CRYPTOTOOLS_RISTRETTO255_REF_H
#define CRYPTOTOOLS_RISTRETTO255_REF_H

#include "ge25519.h"

#ifdef __cplusplus
extern "C" {
#endif

int ristretto255_frombytes(ge25519 *r, const unsigned char encoded[32]);
void ristretto255_tobytes(unsigned char encoded[32], const ge25519 *p);
void ristretto255_from_uniform(ge25519 *r, const unsigned char uniform[64]);

#ifdef __cplusplus
}
#endif

#endif
