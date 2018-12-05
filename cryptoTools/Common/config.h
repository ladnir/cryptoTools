#pragma once


// use the miracl library for curves
#define ENABLE_MIRACL

// use the relic library for curves
//#define ENABLE_RELIC

// include the full GLS header (C++14). If not defined, uses gsl_lite (c++11)
#define ENABLE_FULL_GSL

// compile the circuit library
#define ENABLE_CIRCUITS


// disables the use of assembly based SHA1
//#define NO_INTEL_ASM_SHA1


// Force BLAKE2 to be used as the random oracle 
//#define USE_BLAKE2_AS_RANDOM_ORACLE