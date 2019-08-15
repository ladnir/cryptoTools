#pragma once


// use the miracl library for curves
/* #undef ENABLE_MIRACL */

// use the relic library for curves
/* #undef ENABLE_RELIC */

// compile the circuit library
/* #undef ENABLE_CIRCUITS */

// include the full GSL header (C++14). If not defined, uses gsl_lite (c++11)
#define ENABLE_FULL_GSL ON 

// defined if we should use cpp 14 and undefined means cpp 11
#define ENABLE_CPP_14 ON 

// enables the use of assembly based SHA1
/* #undef ENABLE_NASM */

// Turn on Channel logging for debugging.
//#define ENABLE_NET_LOG ON

// Force BLAKE2 to be used as the random oracle 
//#define USE_BLAKE2_AS_RANDOM_ORACLE
