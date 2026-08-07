#ifndef SC25519_H
#define SC25519_H

typedef struct 
{
  unsigned long long v[4]; 
}
sc25519;

#ifdef __cplusplus
extern "C" {
#endif

void sc25519_from32bytes(sc25519 *r, const unsigned char x[32]);
void sc25519_to32bytes(unsigned char r[32], const sc25519 *x);
void sc25519_window4(signed char r[64], const sc25519 *s); //

#ifdef __cplusplus
}
#endif

#endif

