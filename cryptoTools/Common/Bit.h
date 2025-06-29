# pragma once


#include <stdint.h>
#include <limits>
#include <cstring>
#include <bit>

namespace osuCrypto
{

        // bit_cast

        template<class To, class From>
        To bit_cast(From const& from) noexcept
        {
			return std::bit_cast<To>(from);
        }

        // countl

        template<class T>
        constexpr int countl_zero(T x) noexcept
        {
            return std::countl_zero(x);
        }

        template<class T>
        constexpr int countl_one(T x) noexcept
        {
            return std::countl_one(x);
        }

        // countr

        template<class T>
        int countr_zero(T x) noexcept
        {
            return std::countr_zero(x);
        }

        template<class T>
        constexpr int countr_one(T x) noexcept
        {
            return std::countr_one(x);
        }

        // popcount

        template<class T>
        constexpr int popcount(T x) noexcept
        {
            return std::popcount(x);
        }

        // rotating

        template<class T>
        constexpr T rotl(T x, int s) noexcept
        {
            return std::rotl(x, s);
        }

        template<class T>
        constexpr T rotr(T x, int s) noexcept
        {
            return std::rotr(x, s);

        }

        // integral powers of 2

        template<class T>
        constexpr bool has_single_bit(T x) noexcept
        {
            return std::has_single_bit(x);
        }

        template<class T>
        constexpr T bit_width(T x) noexcept
        {
            return std::bit_width(x);
        }

        template<class T>
        constexpr T bit_floor(T x) noexcept
        {
            return std::bit_floor(x);
        }

        template<class T>
        constexpr T bit_ceil(T x) noexcept
        {
            return std::bit_ceil(x);
        }

} // namespace osuCrypto

