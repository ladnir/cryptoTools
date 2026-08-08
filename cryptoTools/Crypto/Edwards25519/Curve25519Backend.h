#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <cryptoTools/Crypto/Edwards25519/Edwards25519.h>
#include <cryptoTools/Crypto/Edwards25519/Ristretto255.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#if defined(CRYPTOTOOLS_EDWARDS25519_BACKEND_SODIUM) || \
    defined(CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM)
#include <sodium.h>
#endif

#ifdef CRYPTOTOOLS_EDWARDS25519_BACKEND_RELIC
extern "C" {
#include <relic/relic.h>
}
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
        Relic,
        Portable
    };

    template<typename Point, typename Scalar>
    class EdwardsPoint8
    {
    public:
        static constexpr std::size_t lanes = 8;
        static constexpr std::size_t encodedSize = Point::size;

        static EdwardsPoint8 broadcast(const Point& point)
        {
            EdwardsPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = point;
            return result;
        }

        static EdwardsPoint8 hashToCurveElligator2(
            const std::uint8_t* messages, std::size_t messageSize,
            const std::uint8_t* domain, std::size_t domainSize)
        {
            EdwardsPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = Point::hashToCurveElligator2(
                    messages + i * messageSize, messageSize, domain, domainSize);
            return result;
        }

        static EdwardsPoint8 mulGenerator(const std::array<Scalar, lanes>& scalars)
        {
            EdwardsPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = Point::mulGenerator(scalars[i]);
            return result;
        }

        EdwardsPoint8 mul(const Scalar& scalar) const
        {
            EdwardsPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i].mul(scalar);
            return result;
        }

        EdwardsPoint8 mul(const std::array<Scalar, lanes>& scalars) const
        {
            EdwardsPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i].mul(scalars[i]);
            return result;
        }

        EdwardsPoint8 operator+(const EdwardsPoint8& rhs) const
        {
            EdwardsPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i] + rhs.mPoints[i];
            return result;
        }

        EdwardsPoint8 operator-(const EdwardsPoint8& rhs) const
        {
            EdwardsPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i] - rhs.mPoints[i];
            return result;
        }

        EdwardsPoint8 doubled() const
        {
            EdwardsPoint8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i].doubled();
            return result;
        }

        void conditionalMove(const EdwardsPoint8& source,
                             const std::array<std::uint8_t, lanes>& select)
        {
            for (std::size_t i = 0; i != lanes; ++i)
            {
                std::uint8_t dst[encodedSize], src[encodedSize];
                mPoints[i].toBytes(dst);
                source.mPoints[i].toBytes(src);
                const std::uint8_t mask = static_cast<std::uint8_t>(0 - (select[i] & 1));
                for (std::size_t j = 0; j != encodedSize; ++j)
                    dst[j] ^= mask & (dst[j] ^ src[j]);
                (void)mPoints[i].fromBytes(dst);
            }
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

#if defined(CRYPTOTOOLS_EDWARDS25519_BACKEND_SODIUM) || \
    defined(CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM)
    class SodiumEdwardsPoint
    {
    public:
        static constexpr std::size_t size = 32;

        SodiumEdwardsPoint() noexcept : mBytes{} { mBytes[0] = 1; }

        static SodiumEdwardsPoint mulGenerator(const Edwards25519::Scalar& scalar) noexcept
        {
            SodiumEdwardsPoint result;
            std::uint8_t bytes[32];
            scalar.toBytes(bytes);
            if (crypto_scalarmult_ed25519_base_noclamp(
                    result.mBytes.data(), bytes) != 0)
                result = SodiumEdwardsPoint{};
            return result;
        }

        static SodiumEdwardsPoint hashToCurveElligator2(
            const std::uint8_t* message, std::size_t messageSize,
            const std::uint8_t* domain, std::size_t domainSize)
        {
            const auto canonical = Edwards25519::Point::hashToCurveElligator2(
                message, messageSize, domain, domainSize);
            std::uint8_t encoded[size];
            canonical.toBytes(encoded);
            SodiumEdwardsPoint result;
            (void)result.fromBytes(encoded);
            return result;
        }

        SodiumEdwardsPoint mul(const Edwards25519::Scalar& scalar) const noexcept
        {
            SodiumEdwardsPoint result;
            std::uint8_t bytes[32];
            scalar.toBytes(bytes);
            if (isNeutral() ||
                crypto_scalarmult_ed25519_noclamp(
                    result.mBytes.data(), bytes, mBytes.data()) != 0)
                result = SodiumEdwardsPoint{};
            return result;
        }

        SodiumEdwardsPoint operator+(const SodiumEdwardsPoint& rhs) const noexcept
        {
            SodiumEdwardsPoint result;
            crypto_core_ed25519_add(result.mBytes.data(), mBytes.data(), rhs.mBytes.data());
            return result;
        }

        SodiumEdwardsPoint operator-(const SodiumEdwardsPoint& rhs) const noexcept
        {
            SodiumEdwardsPoint result;
            crypto_core_ed25519_sub(result.mBytes.data(), mBytes.data(), rhs.mBytes.data());
            return result;
        }

        SodiumEdwardsPoint doubled() const noexcept { return *this + *this; }

        bool fromBytes(const std::uint8_t bytes[size]) noexcept
        {
            const bool neutral = bytes[0] == 1 && allZero(bytes + 1, size - 1);
            if (!neutral && crypto_core_ed25519_is_valid_point(bytes) != 1)
                return false;
            std::memcpy(mBytes.data(), bytes, size);
            return true;
        }

        void toBytes(std::uint8_t bytes[size]) const noexcept
        {
            std::memcpy(bytes, mBytes.data(), size);
        }

        std::size_t sizeBytes() const noexcept { return size; }
        bool isNeutral() const noexcept
        {
            return mBytes[0] == 1 && allZero(mBytes.data() + 1, size - 1);
        }

    private:
        static bool allZero(const std::uint8_t* data, std::size_t size) noexcept
        {
            std::uint8_t value = 0;
            for (std::size_t i = 0; i != size; ++i) value |= data[i];
            return value == 0;
        }

        std::array<std::uint8_t, size> mBytes;
    };

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

#ifdef CRYPTOTOOLS_EDWARDS25519_BACKEND_RELIC
    class RelicEdwardsPoint
    {
    public:
        static constexpr std::size_t size = 32;

        RelicEdwardsPoint();
        RelicEdwardsPoint(const RelicEdwardsPoint&);
        RelicEdwardsPoint& operator=(const RelicEdwardsPoint&);
        ~RelicEdwardsPoint();

        static void init();
        static RelicEdwardsPoint mulGenerator(const Edwards25519::Scalar& scalar);
        static RelicEdwardsPoint hashToCurveElligator2(
            const std::uint8_t* message, std::size_t messageSize,
            const std::uint8_t* domain, std::size_t domainSize);
        RelicEdwardsPoint mul(const Edwards25519::Scalar& scalar) const;
        RelicEdwardsPoint operator+(const RelicEdwardsPoint& rhs) const;
        RelicEdwardsPoint operator-(const RelicEdwardsPoint& rhs) const;
        RelicEdwardsPoint doubled() const;
        bool fromBytes(const std::uint8_t bytes[size]);
        void toBytes(std::uint8_t bytes[size]) const;
        std::size_t sizeBytes() const noexcept { return size; }
        bool isNeutral() const;

    private:
        ed_t mValue;
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
#elif defined(CRYPTOTOOLS_EDWARDS25519_BACKEND_SODIUM)
    constexpr auto implementation = details::curve25519::Implementation::Sodium;
    using Scalar = Edwards25519::Scalar;
    using Point = details::curve25519::SodiumEdwardsPoint;
    using Point8 = details::curve25519::EdwardsPoint8<Point, Scalar>;
#elif defined(CRYPTOTOOLS_EDWARDS25519_BACKEND_RELIC)
    constexpr auto implementation = details::curve25519::Implementation::Relic;
    using Scalar = Edwards25519::Scalar;
    using Point = details::curve25519::RelicEdwardsPoint;
    using Point8 = details::curve25519::EdwardsPoint8<Point, Scalar>;
#else
    constexpr auto implementation = details::curve25519::Implementation::Portable;
    using Scalar = Edwards25519::Scalar;
    using Point = Edwards25519::Point;
    using Point8 = Edwards25519::Point8;
#endif

    inline void init()
    {
#ifdef CRYPTOTOOLS_EDWARDS25519_BACKEND_RELIC
        Point::init();
#elif defined(CRYPTOTOOLS_EDWARDS25519_BACKEND_SODIUM)
        const int initialized = sodium_init();
        (void)initialized;
#endif
    }
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

#if defined(CRYPTOTOOLS_EDWARDS25519_BACKEND_SODIUM) || \
    defined(CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM)
template<>
struct Hashable<details::curve25519::SodiumEdwardsPoint, void> : std::true_type
{
    template<typename Hasher>
    static void hash(const details::curve25519::SodiumEdwardsPoint& point,
                     Hasher& hasher)
    {
        std::uint8_t encoded[details::curve25519::SodiumEdwardsPoint::size];
        point.toBytes(encoded);
        hasher.Update(encoded, sizeof(encoded));
    }
};

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

#ifdef CRYPTOTOOLS_EDWARDS25519_BACKEND_RELIC
template<>
struct Hashable<details::curve25519::RelicEdwardsPoint, void> : std::true_type
{
    template<typename Hasher>
    static void hash(const details::curve25519::RelicEdwardsPoint& point,
                     Hasher& hasher)
    {
        std::uint8_t encoded[details::curve25519::RelicEdwardsPoint::size];
        point.toBytes(encoded);
        hasher.Update(encoded, sizeof(encoded));
    }
};
#endif

template<typename Point, typename Scalar>
struct Hashable<details::curve25519::EdwardsPoint8<Point, Scalar>, void>
    : std::true_type
{
    template<typename Hasher>
    static void hash(
        const details::curve25519::EdwardsPoint8<Point, Scalar>& points,
        Hasher& hasher)
    {
        std::uint8_t encoded[
            details::curve25519::EdwardsPoint8<Point, Scalar>::lanes *
            details::curve25519::EdwardsPoint8<Point, Scalar>::encodedSize];
        points.toBytes(encoded);
        hasher.Update(encoded, sizeof(encoded));
    }
};

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
