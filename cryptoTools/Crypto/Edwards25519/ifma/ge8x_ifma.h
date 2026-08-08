#ifndef GE8X_IFMA_H
#define GE8X_IFMA_H

#include <immintrin.h>

#include "../portable/fe25519.h"
#include "../portable/ge25519.h"
#include "../portable/sc25519.h"

#if defined(_MSC_VER)
#define CRYPTOTOOLS_EDWARDS25519_ALIGN64 __declspec(align(64))
#else
#define CRYPTOTOOLS_EDWARDS25519_ALIGN64 __attribute__((aligned(64)))
#endif

typedef struct CRYPTOTOOLS_EDWARDS25519_ALIGN64 {
    __m512i limb[5];
} gfe8x;

typedef struct CRYPTOTOOLS_EDWARDS25519_ALIGN64 {
    gfe8x x;
    gfe8x y;
    gfe8x z;
    gfe8x t;
} ge8x;

#undef CRYPTOTOOLS_EDWARDS25519_ALIGN64

#ifdef __cplusplus
extern "C" {
#endif

void ge8x_setneutral(ge8x* r);
void ge8x_from_ge25519(ge8x* r, const ge25519* p);
void ge8x_from_ge25519s(ge8x* r, const ge25519 p[8]);
void ge8x_to_ge25519s(ge25519 p[8], const ge8x* r);
void ge8x_add(ge8x* r, const ge8x* p, const ge8x* q);
void ge8x_sub(ge8x* r, const ge8x* p, const ge8x* q);
void ge8x_double(ge8x* r, const ge8x* p);
void ge8x_cmovs(ge8x* r, const ge8x* p, const unsigned char select[8]);

void ge8x_map_to_curve_elligator2(ge8x* r, const fe25519 u[8]);
void ge8x_ristretto_from_uniform(ge8x* r, const unsigned char uniform[8 * 64]);
int ge8x_ristretto_frombytes(ge8x* r, const unsigned char encoded[8 * 32]);
void ge8x_ristretto_tobytes(unsigned char encoded[8 * 32], const ge8x* p);
int ge8x_unpack_vartime(ge8x* r, const unsigned char encoded[8 * 32]);
void ge8x_pack(unsigned char encoded[8 * 32], const ge8x* p);

void ge8x_scalarmult(ge8x* r, const ge8x* p, const sc25519* scalar);
void ge8x_scalarsmults(ge8x* r, const ge8x* p, const sc25519 scalars[8]);
void ge8x_scalarsmults_base(ge8x* r, const sc25519 scalars[8]);

#ifdef __cplusplus
}
#endif

#endif
