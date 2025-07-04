#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.

#include <cstdint>
#include <memory>
#include "cryptoTools/Common/config.h"
#include "block.h"

#ifdef ENABLE_SPAN_LITE
#ifndef span_CONFIG_SELECT_SPAN
    #define span_CONFIG_SELECT_SPAN 1
#endif
#include <nonstd/span.hpp>
#else
#include <span>
#endif

#include "Bit.h"

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
#ifdef ENABLE_SPAN_LITE
    template<typename T> using span = nonstd::span<T>;
#else
    template<typename T> using span = std::span<T>;
#endif

    typedef uint64_t u64;
    typedef int64_t i64;
    typedef uint32_t u32;
    typedef int32_t i32;
    typedef uint16_t u16;
    typedef int16_t i16;
    typedef uint8_t u8;
    typedef int8_t i8;

    constexpr u64 divCeil(u64 val, u64 d) { return (val + d - 1) / d; }
    constexpr u64 divNearest(u64 val, u64 d) { return (val + (d/2)) / d; } // Ties go towards infinity.
    constexpr u64 roundUpTo(u64 val, u64 step) { return divCeil(val, step) * step; }

    inline constexpr u64 log2ceil(u64 x)
    {
        return bit_width(x - 1);
    }
    inline u64 log2floor(u64 x)
    {
        return bit_width(x) - 1;
    }

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

    enum class AllocType
    {
        Uninitialized,
        Zeroed
    };




    template<typename T, typename = void>
    struct has_data_member_func : std::false_type
    {
    };

    template <typename T>
    struct has_data_member_func < T, std::void_t<
        // must have value_type
        typename T::value_type,

        // must have a data() member fn
        decltype(std::declval<T>().data()),

        // must return value_type* or const value_type*
        std::enable_if_t<
        std::is_same<
        decltype(std::declval<T>().data()),
        typename T::value_type*
        >::value
        ||
        // pre CPP 17 std::string returns a const pointer. So we
        // will allow this case.
        std::is_same<
        decltype(std::declval<T>().data()),
        const typename T::value_type*
        >::value
        >
        >>
        : std::true_type{};


    template<typename T, typename = void>
    struct has_size_member_func : std::false_type
    {
    };

    template <typename T>
    struct has_size_member_func <T, std::void_t<
        // must have size type
        typename T::size_type,

        // must have a size() member fn
        decltype(std::declval<T>().size()),

        // must return size_type
        std::enable_if_t<
        std::is_same<
        decltype(std::declval<T>().size()),
        typename T::size_type
        >::value
        >
        >>
        : std::true_type{};


    template<class Container, typename = void>
    struct is_container_type : std::false_type
    {
    };

    template<class Container>
    struct is_container_type < Container, std::void_t <
        std::enable_if_t<has_data_member_func<typename std::remove_reference<Container>::type>::value>,
        std::enable_if_t<has_size_member_func<typename std::remove_reference<Container>::type>::value>
        >> :
        std::true_type {};

    class BitVector;
    template<typename T>
    auto asSpan(T&& t)
    {
        static_assert(std::is_pointer_v<T> == false);

        if constexpr (std::is_same_v<std::remove_cvref_t<T>, BitVector>)
        {
            return t.template getSpan<u8>();
        }
        if constexpr (is_container_type<T>::value)
        {
            using U = std::remove_reference_t<decltype(*t.data())>;
            return span<U>(t.data(), t.size());
        }
        else if constexpr (std::is_trivial_v<std::remove_reference_t<T>>)
        {
            return std::span<std::remove_reference_t<T>, 1>(&t, &t + 1);
        }
        else
        {
            static_assert(
                is_container_type<T>::value ||
                std::is_trivial_v<std::remove_reference_t<T>>
                );
        }
    }

    template<typename D, typename S>
    OC_FORCEINLINE void copyBytes(D&& dst, S&& src)
    {
        auto d = asSpan(dst);
        auto s = asSpan(src);
        if (d.size_bytes() != s.size_bytes())
            throw RTE_LOC;
        static_assert(std::is_trivially_copyable_v<std::remove_reference_t<decltype(*d.data())>>);
        static_assert(std::is_trivially_copyable_v<std::remove_reference_t<decltype(*s.data())>>);
        if (d.size())
            std::memcpy(d.data(), s.data(), d.size_bytes());
    }

    template<typename D, typename S>
    OC_FORCEINLINE void copyBytesMin(D&& dst, S&& src)
    {
        auto d = asSpan(dst);
        auto s = asSpan(src);
        auto size = std::min(s.size_bytes(), d.size_bytes());
        static_assert(std::is_trivially_copyable_v<std::remove_reference_t<decltype(*d.data())>>);
        static_assert(std::is_trivially_copyable_v<std::remove_reference_t<decltype(*s.data())>>);
        if (size)
            std::memcpy(d.data(), s.data(), size);
    }

    template<typename D>
    OC_FORCEINLINE void setBytes(D&& dst, char v)
    {
        auto d = asSpan(dst);
        static_assert(std::is_trivially_copyable_v<std::remove_reference_t<decltype(*d.data())>>);
        if (d.size())
            std::memset(d.data(), v, d.size_bytes());
    }
}

namespace oc = osuCrypto;
