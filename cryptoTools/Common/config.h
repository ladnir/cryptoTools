#pragma once


// use the miracl library for curves
/* #undef ENABLE_MIRACL */

// use the relic library for curves
#define ENABLE_RELIC ON 

// compile the circuit library
/* #undef ENABLE_CIRCUITS */

// include the full GSL header (C++14). If not defined, uses gsl_lite (c++11)
#define ENABLE_FULL_GSL ON 

// defined if we should use cpp 14 and undefined means cpp 11
#define ENABLE_CPP_14 ON 

// enables the use of assembly based SHA1
/* #undef ENABLE_NASM */

// Turn on Channel logging for debugging.
/* #undef ENABLE_NET_LOG */


// enable the wolf ssl socket layer.
/* #undef ENABLE_WOLFSSL */

// enable integration with boost for networking.
#define ENABLE_BOOST ON

// enable the use of intel SSE instructions.
#define ENABLE_SSE ON

// enable the use of the portable AES implementation.
/* #undef ENABLE_PORTABLE_AES */

#if (defined(_MSC_VER) || defined(__SSE2__)) && defined(ENABLE_SSE)
#define ENABLE_SSE_BLAKE2 ON
#define OC_ENABLE_SSE2 ON
#endif

#if (defined(_MSC_VER) || defined(__PCLMUL__)) && defined(ENABLE_SSE)
#define OC_ENABLE_PCLMUL
#endif

#if (defined(_MSC_VER) || defined(__AES__)) && defined(ENABLE_SSE)
#define OC_ENABLE_AESNI ON
#else
#define OC_ENABLE_PORTABLE_AES ON
#endif
