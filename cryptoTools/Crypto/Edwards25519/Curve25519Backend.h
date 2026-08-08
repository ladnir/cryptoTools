#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <cryptoTools/Crypto/Edwards25519/Edwards25519.h>
#include <cryptoTools/Crypto/Edwards25519/Ristretto255.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#ifdef CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM
#include <sodium.h>
#endif

namespace osuCrypto
{
namespace details
{
namespace curve25519
{
    enum class Implementation
    {
        Avx512Ifma,
        Assembly,
        Sodium,
        Portable
    };

    template<typename Point, typename Scalar>
    class RistrettoPoint8
    {
    public:
        static constexpr std::size_t lanes = 8;
        static constexpr std::size_t encodedSize = Point::size;

        static RistrettoPoint8 broadcast(const Point& point)
        {
            RistrettoPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = point;
            return result;
        }

        static RistrettoPoint8 fromUniformBytes(
            const std::uint8_t uniform[lanes * Point::fromHashLength])
        {
            RistrettoPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = Point::fromUniformBytes(
                    uniform + i * Point::fromHashLength);
            return result;
        }

        static RistrettoPoint8 mulGenerator(const std::array<Scalar, lanes>& scalars)
        {
            RistrettoPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = Point::mulGenerator(scalars[i]);
            return result;
        }

        RistrettoPoint8 mul(const Scalar& scalar) const
        {
            RistrettoPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i].mul(scalar);
            return result;
        }

        RistrettoPoint8 mul(const std::array<Scalar, lanes>& scalars) const
        {
            RistrettoPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i].mul(scalars[i]);
            return result;
        }

        RistrettoPoint8 operator+(const RistrettoPoint8& rhs) const
        {
            RistrettoPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i] + rhs.mPoints[i];
            return result;
        }

        RistrettoPoint8 operator-(const RistrettoPoint8& rhs) const
        {
            RistrettoPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i] - rhs.mPoints[i];
            return result;
        }

        RistrettoPoint8 doubled() const
        {
            RistrettoPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i].doubled();
            return result;
        }

        bool fromBytes(const std::uint8_t bytes[lanes * encodedSize])
        {
            for (std::size_t i = 0; i != lanes; ++i)
                if (!mPoints[i].fromBytes(bytes + i * encodedSize))
                    return false;
            return true;
        }

        void toBytes(std::uint8_t bytes[lanes * encodedSize]) const
        {
            for (std::size_t i = 0; i != lanes; ++i)
                mPoints[i].toBytes(bytes + i * encodedSize);
        }

    private:
        std::array<Point, lanes> mPoints;
    };

#ifdef CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM
    class SodiumRistrettoPoint
    {
    public:
        static constexpr std::size_t size = 32;
        static constexpr std::size_t fromHashLength = 64;

        SodiumRistrettoPoint() noexcept : mBytes{} {}
        explicit SodiumRistrettoPoint(PRNG& prng)
        {
            std::uint8_t uniform[fromHashLength];
            prng.get(uniform, sizeof(uniform));
            *this = fromUniformBytes(uniform);
        }

        static SodiumRistrettoPoint mulGenerator(const Ristretto255::Scalar& scalar) noexcept
        {
            SodiumRistrettoPoint result;
            std::uint8_t bytes[32];
            scalar.toBytes(bytes);
            if (crypto_scalarmult_ristretto255_base(
                    result.mBytes.data(), bytes) != 0)
                result = SodiumRistrettoPoint{};
            return result;
        }

        static SodiumRistrettoPoint fromUniformBytes(
            const std::uint8_t uniform[fromHashLength]) noexcept
        {
            SodiumRistrettoPoint result;
            crypto_core_ristretto255_from_hash(result.mBytes.data(), uniform);
            return result;
        }

        static SodiumRistrettoPoint fromHash(
            const std::uint8_t uniform[fromHashLength]) noexcept
        {
            return fromUniformBytes(uniform);
        }

        static SodiumRistrettoPoint fromHash(RandomOracle hash)
        {
            std::uint8_t uniform[fromHashLength];
            hash.Final(uniform);
            return fromUniformBytes(uniform);
        }

        SodiumRistrettoPoint mul(const Ristretto255::Scalar& scalar) const noexcept
        {
            SodiumRistrettoPoint result;
            std::uint8_t bytes[32];
            scalar.toBytes(bytes);
            if (isNeutral() ||
                crypto_scalarmult_ristretto255(
                    result.mBytes.data(), bytes, mBytes.data()) != 0)
                result = SodiumRistrettoPoint{};
            return result;
        }

        SodiumRistrettoPoint operator*(const Ristretto255::Scalar& scalar) const noexcept
        {
            return mul(scalar);
        }

        SodiumRistrettoPoint& operator*=(const Ristretto255::Scalar& scalar) noexcept
        {
            return *this = mul(scalar);
        }

        SodiumRistrettoPoint operator+(const SodiumRistrettoPoint& rhs) const noexcept
        {
            SodiumRistrettoPoint result;
            crypto_core_ristretto255_add(result.mBytes.data(), mBytes.data(), rhs.mBytes.data());
            return result;
        }

        SodiumRistrettoPoint operator-(const SodiumRistrettoPoint& rhs) const noexcept
        {
            SodiumRistrettoPoint result;
            crypto_core_ristretto255_sub(result.mBytes.data(), mBytes.data(), rhs.mBytes.data());
            return result;
        }

        SodiumRistrettoPoint& operator+=(const SodiumRistrettoPoint& rhs) noexcept
        {
            return *this = *this + rhs;
        }

        SodiumRistrettoPoint& operator-=(const SodiumRistrettoPoint& rhs) noexcept
        {
            return *this = *this - rhs;
        }

        SodiumRistrettoPoint doubled() const noexcept { return *this + *this; }

        bool fromBytes(const std::uint8_t bytes[size]) noexcept
        {
            if (crypto_core_ristretto255_is_valid_point(bytes) != 1)
                return false;
            std::memcpy(mBytes.data(), bytes, size);
            return true;
        }

        void toBytes(std::uint8_t bytes[size]) const noexcept
        {
            std::memcpy(bytes, mBytes.data(), size);
        }

        std::size_t sizeBytes() const noexcept { return size; }
        bool operator==(const SodiumRistrettoPoint& rhs) const noexcept
        {
            return sodium_memcmp(mBytes.data(), rhs.mBytes.data(), size) == 0;
        }
        bool operator!=(const SodiumRistrettoPoint& rhs) const noexcept
        {
            return !(*this == rhs);
        }

    private:
        bool isNeutral() const noexcept
        {
            std::uint8_t value = 0;
            for (auto byte : mBytes) value |= byte;
            return value == 0;
        }

        std::array<std::uint8_t, size> mBytes;
    };
#endif

}
}

namespace Edwards25519
{
namespace Backend
{
    constexpr std::size_t encodedSize = Edwards25519::encodedSize;
    constexpr std::size_t lanes = Edwards25519::lanes;

#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA)
    constexpr auto implementation = details::curve25519::Implementation::Avx512Ifma;
    using Scalar = Edwards25519::Scalar;
    using Point = Edwards25519::Point;
    using Point8 = Edwards25519::Point8;
#elif defined(CRYPTOTOOLS_EDWARDS25519_ASM)
    constexpr auto implementation = details::curve25519::Implementation::Assembly;
    using Scalar = Edwards25519::Scalar;
    using Point = Edwards25519::Point;
    using Point8 = Edwards25519::Point8;
#else
    constexpr auto implementation = details::curve25519::Implementation::Portable;
    using Scalar = Edwards25519::Scalar;
    using Point = Edwards25519::Point;
    using Point8 = Edwards25519::Point8;
#endif

    inline void init() noexcept {}
}
}

namespace Ristretto255
{
namespace Backend
{
    constexpr std::size_t encodedSize = Ristretto255::encodedSize;
    constexpr std::size_t uniformSize = Ristretto255::uniformSize;
    constexpr std::size_t lanes = Ristretto255::lanes;

#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA)
    constexpr auto implementation = details::curve25519::Implementation::Avx512Ifma;
    using Scalar = Ristretto255::Scalar;
    using Point = Ristretto255::Point;
    using Point8 = Ristretto255::Point8;
#elif defined(CRYPTOTOOLS_EDWARDS25519_ASM)
    constexpr auto implementation = details::curve25519::Implementation::Assembly;
    using Scalar = Ristretto255::Scalar;
    using Point = Ristretto255::Point;
    using Point8 = Ristretto255::Point8;
#elif defined(CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM)
    constexpr auto implementation = details::curve25519::Implementation::Sodium;
    using Scalar = Ristretto255::Scalar;
    using Point = details::curve25519::SodiumRistrettoPoint;
    using Point8 = details::curve25519::RistrettoPoint8<Point, Scalar>;
#else
    constexpr auto implementation = details::curve25519::Implementation::Portable;
    using Scalar = Ristretto255::Scalar;
    using Point = Ristretto255::Point;
    using Point8 = Ristretto255::Point8;
#endif

    inline void init() noexcept
    {
#ifdef CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM
        const int initialized = sodium_init();
        (void)initialized;
#endif
    }
}
}

#ifdef CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM
template<>
struct Hashable<details::curve25519::SodiumRistrettoPoint, void> : std::true_type
{
    template<typename Hasher>
    static void hash(const details::curve25519::SodiumRistrettoPoint& point,
                     Hasher& hasher)
    {
        std::uint8_t encoded[details::curve25519::SodiumRistrettoPoint::size];
        point.toBytes(encoded);
        hasher.Update(encoded, sizeof(encoded));
    }
};
#endif

template<typename Point, typename Scalar>
struct Hashable<details::curve25519::RistrettoPoint8<Point, Scalar>, void>
    : std::true_type
{
    template<typename Hasher>
    static void hash(
        const details::curve25519::RistrettoPoint8<Point, Scalar>& points,
        Hasher& hasher)
    {
        std::uint8_t encoded[
            details::curve25519::RistrettoPoint8<Point, Scalar>::lanes *
            details::curve25519::RistrettoPoint8<Point, Scalar>::encodedSize];
        points.toBytes(encoded);
        hasher.Update(encoded, sizeof(encoded));
    }
};
}
