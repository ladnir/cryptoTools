#ifndef GE4X_H
#define GE4X_H

#include "ge25519.h"
#ifdef CRYPTOTOOLS_EDWARDS25519_ASM
#include "gfe4x.h"
#endif
#include "sc25519.h"

/* Four-lane Edwards25519 arithmetic in structure-of-arrays form.
 * Values are 32-byte aligned; keep batches intact to preserve the assembly
 * implementation's fixed-width execution model. Hashing and OT operations
 * are intentionally outside this interface. */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CRYPTOTOOLS_EDWARDS25519_ASM

typedef struct{

	gfe4x x;
	gfe4x y;
	gfe4x z;
	gfe4x t;

} ge4x;

typedef struct{

	gfe4x x;
	gfe4x y;
	gfe4x z;
	gfe4x t;

} ge4x_p1p1;

typedef struct{

	gfe4x x;
	gfe4x y;
	gfe4x z;

} ge4x_p2;

typedef struct{

	gfe4x x;
	gfe4x y;
	gfe4x z;

} ge4x_niels;

#else

/* The portable backend keeps four independent extended points.  Callers use
 * the same fixed-width API; only the private representation changes. */
typedef struct {
    ge25519 lane[4];
} ge4x;

typedef struct {
    ge25519_p1p1 lane[4];
} ge4x_p1p1;

typedef struct {
    ge25519_p2 lane[4];
} ge4x_p2;

typedef struct {
    ge25519_niels lane[4];
} ge4x_niels;

#endif

void ge4x_cmovs(ge4x *r, const ge4x *x, unsigned char * b);

void ge4x_setneutral(ge4x * a);
void ge4x_neg(ge4x * a, const ge4x * b);
void ge4x_add(ge4x * a, const ge4x * b, const ge4x * c);
void ge4x_sub(ge4x * c, const ge4x * a, const ge4x * b);
void ge4x_double(ge4x * a, const ge4x * b);

void ge4x_maketable(ge4x (*table)[8], const ge4x * b, int dist);

void ge4x_scalarmults_base(ge4x * a, const sc25519 * s);
void ge4x_scalarmults(ge4x * a, ge4x * b, const sc25519 * s);

void ge4x_scalarsmults_base(ge4x * a, const sc25519 * s);
void ge4x_scalarsmults(ge4x * a, ge4x * b, const sc25519 * s);
void ge4x_scalarsmults_table(ge4x * a, ge4x (*table)[8], const sc25519 * s, int dist);

int ge4x_unpack_vartime(ge4x * r, unsigned char p[128]);
void ge4x_pack(unsigned char r[128], const ge4x *p);

/* Replicate one scalar point into all four lanes without packing it. */
void ge4x_from_ge25519(ge4x *r, const ge25519 *p);

#ifdef __cplusplus
}
#endif

#endif //ifndef GE4X_H

