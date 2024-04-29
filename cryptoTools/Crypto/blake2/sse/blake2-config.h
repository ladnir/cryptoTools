/*
   BLAKE2 reference source code package - optimized C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#include "cryptoTools/Common/config.h"
#ifdef ENABLE_SSE_BLAKE2

#ifndef BLAKE2_CONFIG_H
#define BLAKE2_CONFIG_H


/* These don't work everywhere */
#define HAVE_SSE2

#ifdef ENABLE_AVX
#define HAVE_SSSE3
#define HAVE_SSE41
#define HAVE_AVX
#endif


#ifdef HAVE_AVX2
#ifndef HAVE_AVX
#define HAVE_AVX
#endif
#endif

#ifdef HAVE_XOP
#ifndef HAVE_AVX
#define HAVE_AVX
#endif
#endif

#ifdef HAVE_AVX
#ifndef HAVE_SSE41
#define HAVE_SSE41
#endif
#endif

#ifdef HAVE_SSE41
#ifndef HAVE_SSSE3
#define HAVE_SSSE3
#endif
#endif

#ifdef HAVE_SSSE3
#define HAVE_SSE2
#endif

#if !defined(HAVE_SSE2)
#error "This code requires at least SSE2."
#endif

#endif
#endif
