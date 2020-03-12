#pragma once
#include "cryptoTools/Common/config.h"
#include <cstdint>
#include <array>
#include <iostream>

#ifdef ENABLE_SSE
#include <emmintrin.h>
#include <smmintrin.h>
#endif

namespace osuCrypto
{

#ifdef ENABLE_SSE
    static_assert(0, "...");
    using block = __m128i;
    inline block toBlock(std::uint64_t high_u64, std::uint64_t low_u64) { return _mm_set_epi64x(high_u64, low_u64); }
    inline block toBlock(std::uint64_t low_u64) { return toBlock(0, low_u64); }
    inline block toBlock(std::uint8_t* data) { return toBlock(((std::uint64_t*)data)[1], ((std::uint64_t*)data)[0]); }
#else

    struct block
    {
        std::uint64_t mData[2];


        inline bool operator<(const osuCrypto::block& rhs)
        {
            return mData[1] < rhs.mData[1] || (mData[1] == rhs.mData[1] && mData[0] < rhs.mData[0]);
        }

        inline osuCrypto::block operator^(const osuCrypto::block& rhs) const
        {
            auto ret = *this;
            ret.mData[0] ^= rhs.mData[0];
            ret.mData[1] ^= rhs.mData[1];
            return ret;
        }
        inline osuCrypto::block operator&(const osuCrypto::block& rhs)const
        {
            auto ret = *this;
            ret.mData[0] &= rhs.mData[0];
            ret.mData[1] &= rhs.mData[1];
            return ret;
        }

        inline osuCrypto::block operator|(const osuCrypto::block& rhs)const
        {
            auto ret = *this;
            ret.mData[0] |= rhs.mData[0];
            ret.mData[1] |= rhs.mData[1];
            return ret;
        }
        inline osuCrypto::block operator<<(const std::uint8_t& rhs)const
        {
            auto ret = *this;
            ret.mData[0] <<= rhs;
            ret.mData[1] <<= rhs;
            return ret;
        }
        inline osuCrypto::block operator>>(const std::uint8_t& rhs)const
        {
            auto ret = *this;
            ret.mData[0] >>= rhs;
            ret.mData[1] >>= rhs;
            return ret;
        }
        inline osuCrypto::block operator+(const osuCrypto::block& rhs)const
        {
            auto ret = *this;
            ret.mData[0] += rhs.mData[0];
            ret.mData[1] += rhs.mData[1];
            return ret;
        }


    };

    inline block toBlock(std::uint64_t high_u64, std::uint64_t low_u64)
    {
        block ret;
        ret.mData[0] = low_u64;
        ret.mData[1] = high_u64;
        return ret;
    }
    inline block toBlock(std::uint64_t low_u64) { return toBlock(0, low_u64); }
    inline block toBlock(std::uint8_t* data) { return toBlock(((std::uint64_t*)data)[1], ((std::uint64_t*)data)[0]); }

#endif

    extern const block ZeroBlock;
    extern const block OneBlock;
    extern const block AllOneBlock;
    extern const block CCBlock;
    extern const std::array<block, 2> zeroAndAllOne;
}

std::ostream& operator<<(std::ostream& out, const osuCrypto::block& block);
namespace osuCrypto
{
    using ::operator<<;
}

#ifdef ENABLE_SSE

inline bool eq(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    osuCrypto::block neq = _mm_xor_si128(lhs, rhs);
    return _mm_test_all_zeros(neq, neq) != 0;
}

inline bool neq(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    osuCrypto::block neq = _mm_xor_si128(lhs, rhs);
    return _mm_test_all_zeros(neq, neq) == 0;
}

#ifdef _MSC_VER
inline bool operator<(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return lhs.m128i_u64[1] < rhs.m128i_u64[1] || (eq(lhs, rhs) && lhs.m128i_u64[0] < rhs.m128i_u64[0]);
}

inline osuCrypto::block operator^(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return _mm_xor_si128(lhs, rhs);
}
inline osuCrypto::block operator&(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return _mm_and_si128(lhs, rhs);
}

inline osuCrypto::block operator|(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return _mm_or_si128(lhs, rhs);
}
inline osuCrypto::block operator<<(const osuCrypto::block& lhs, const std::uint8_t& rhs)
{
    return _mm_slli_epi64(lhs, rhs);
}
inline osuCrypto::block operator>>(const osuCrypto::block& lhs, const std::uint8_t& rhs)
{
    return _mm_srli_epi64(lhs, rhs);
}
inline osuCrypto::block operator+(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return _mm_add_epi64(lhs, rhs);
}
#endif
#else
inline bool eq(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return lhs.mData[0] == rhs.mData[0] && lhs.mData[1] == rhs.mData[1];
}

inline bool neq(const osuCrypto::block& lhs, const osuCrypto::block& rhs)
{
    return !eq(lhs, rhs);
}

#endif
