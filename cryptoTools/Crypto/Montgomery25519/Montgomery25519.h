#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <cryptoTools/Crypto/Curve25519Implementation.h>
#include <cryptoTools/Crypto/Hashable.h>
#include <cryptoTools/Crypto/PRNG.h>

namespace osuCrypto
{
namespace Montgomery25519
{
    constexpr std::size_t encodedSize = 32;
    constexpr std::size_t lanes = 8;

    // An unclamped 255-bit integer. Bit 255 is always ignored, exactly as in
    // osu-crypto/libsodium's crypto_scalarmult_noclamp().
    class Scalar
    {
    public:
        Scalar() noexcept = default;
        explicit Scalar(const std::uint8_t bytes[encodedSize]) noexcept;
        explicit Scalar(PRNG& prng) noexcept;

        void randomize(PRNG& prng) noexcept;
        void fromBytes(const std::uint8_t bytes[encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[encodedSize]) const noexcept;

        static constexpr std::size_t size = encodedSize;

    private:
        std::array<std::uint8_t, encodedSize> mBytes{};
        friend class Point;
        friend class Point8;
    };

    // A raw Montgomery u-coordinate. It intentionally does not distinguish
    // Curve25519 from its quadratic twist.
    class Point
    {
    public:
        Point() noexcept = default;
        explicit Point(const std::uint8_t bytes[encodedSize]) noexcept;

        static Point fromU(std::uint8_t u) noexcept;
        bool fromBytes(const std::uint8_t bytes[encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[encodedSize]) const noexcept;

        bool tryMul(const Scalar& scalar, Point& result) const noexcept;
        Point mul(const Scalar& scalar) const;
        Point operator*(const Scalar& scalar) const { return mul(scalar); }
        Point& operator*=(const Scalar& scalar) { return *this = mul(scalar); }

        std::size_t sizeBytes() const noexcept { return encodedSize; }
        bool operator==(const Point& rhs) const noexcept;
        bool operator!=(const Point& rhs) const noexcept { return !(*this == rhs); }

        static const Point primeSubgroupGenerator;
        static const Point primeTwistSubgroupGenerator;
        static const Point wholeGroupGenerator;
        static const Point wholeTwistGroupGenerator;
        static constexpr std::size_t size = encodedSize;

    private:
        std::array<std::uint8_t, encodedSize> mBytes{};
        friend class Point8;
    };

    inline Point operator*(const Scalar& scalar, const Point& point)
    {
        return point.mul(scalar);
    }

    class Point8
    {
    public:
        Point8() noexcept = default;

        static Point8 broadcast(const Point& point) noexcept;
        static Point8 fromPoints(const std::array<Point, lanes>& points) noexcept;
        bool fromBytes(const std::uint8_t bytes[lanes * encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[lanes * encodedSize]) const noexcept;

        bool tryMul(const Scalar& scalar, Point8& result) const noexcept;
        bool tryMul(const std::array<Scalar, lanes>& scalars,
                    Point8& result) const noexcept;
        Point8 mul(const Scalar& scalar) const;
        Point8 mul(const std::array<Scalar, lanes>& scalars) const;
        Point8 operator*(const Scalar& scalar) const { return mul(scalar); }

    private:
        std::array<std::uint8_t, lanes * encodedSize> mBytes{};
    };

namespace Backend
{
    constexpr std::size_t encodedSize = Montgomery25519::encodedSize;
    constexpr std::size_t lanes = Montgomery25519::lanes;

#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA)
    constexpr auto implementation =
        details::curve25519::Implementation::Avx512Ifma;
#elif defined(SODIUM_MONTGOMERY)
    constexpr auto implementation = details::curve25519::Implementation::Sodium;
#else
    constexpr auto implementation = details::curve25519::Implementation::Portable;
#endif

    using Scalar = Montgomery25519::Scalar;
    using Point = Montgomery25519::Point;
    using Point8 = Montgomery25519::Point8;

    void init() noexcept;
}
}

template<>
struct Hashable<Montgomery25519::Point, void> : std::true_type
{
    template<typename Hasher>
    static void hash(const Montgomery25519::Point& point, Hasher& hasher)
    {
        std::uint8_t encoded[Montgomery25519::encodedSize];
        point.toBytes(encoded);
        hasher.Update(encoded, sizeof(encoded));
    }
};

template<>
struct Hashable<Montgomery25519::Point8, void> : std::true_type
{
    template<typename Hasher>
    static void hash(const Montgomery25519::Point8& points, Hasher& hasher)
    {
        std::uint8_t encoded[
            Montgomery25519::lanes * Montgomery25519::encodedSize];
        points.toBytes(encoded);
        hasher.Update(encoded, sizeof(encoded));
    }
};
}
