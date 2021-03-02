#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.

#include <cstdint>
#include <memory>
#include "cryptoTools/Common/config.h"
#include "block.h"

#ifdef ENABLE_FULL_GSL
#include <cryptoTools/gsl/span>
#else
#include <cryptoTools/gsl/gls-lite.hpp>
#endif

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define LOCATION __FILE__ ":" STRINGIZE(__LINE__)
#define RTE_LOC std::runtime_error(LOCATION)

#ifdef _MSC_VER
    #ifndef _WIN32_WINNT
        // compile for win 7 and up.
        #define _WIN32_WINNT 0x0601
    #endif 
	#pragma warning( disable : 4018) // signed unsigned comparison warning
	#define TODO(x) __pragma(message (__FILE__ ":" STRINGIZE(__LINE__) " Warning:TODO - " #x))
#else
	#define TODO(x)
#endif

// add instrinsics names that intel knows but clang doesn't…
#ifdef __clang__
#define _mm_cvtsi128_si64x _mm_cvtsi128_si64
#endif


namespace osuCrypto {
    template<typename T> using ptr = T*;
    template<typename T> using uPtr = std::unique_ptr<T>;
    template<typename T> using sPtr = std::shared_ptr<T>;
    template<typename T> using span = gsl::span<T>;

    typedef uint64_t u64;
    typedef int64_t i64;
    typedef uint32_t u32;
    typedef int32_t i32;
    typedef uint16_t u16;
    typedef int16_t i16;
    typedef uint8_t u8;
    typedef int8_t i8;

    inline u64 roundUpTo(u64 val, u64 step) { return ((val + step - 1) / step) * step; }

    u64 log2ceil(u64);
    u64 log2floor(u64);

    block sysRandomSeed();



    static inline uint64_t mod64(uint64_t word, uint64_t p)
    {
#ifdef __SIZEOF_INT128__ 
        return (uint64_t)(((__uint128_t)word * (__uint128_t)p) >> 64);
#elif defined(_MSC_VER) && defined(_WIN64)
        uint64_t highProduct;
        _umul128(word, p, &highProduct); 
        return highProduct;
        unsigned __int64 _umul128(
            unsigned __int64 Multiplier,
            unsigned __int64 Multiplicand,
            unsigned __int64* HighProduct
        );
#else
        return word % p; 
#endif 
    }

}

#ifdef _MSC_VER
#ifdef ENABLE_RELIC
#pragma comment(lib, "relic_s.lib")
#endif

#ifdef ENABLE_MIRACL
#pragma comment(lib, "miracl.lib")
#endif

#ifdef ENABLE_WOLFSSL
#pragma comment(lib, "wolfssl.lib")
#endif
#endif

namespace oc = osuCrypto;
