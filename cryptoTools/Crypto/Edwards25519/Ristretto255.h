#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <cryptoTools/Crypto/Hashable.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

extern "C" {
#include <cryptoTools/Crypto/Edwards25519/ge25519.h>
#include <cryptoTools/Crypto/Edwards25519/ristretto255_ref.h>
#ifndef CRYPTOTOOLS_EDWARDS25519_IFMA
#include <cryptoTools/Crypto/Edwards25519/ge4x.h>
#endif
}

#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
#include <cryptoTools/Crypto/Edwards25519/ge8x_ifma.h>
#endif

namespace osuCrypto
{
namespace Ristretto255
{
    constexpr std::size_t encodedSize = 32;
    constexpr std::size_t uniformSize = 64;
    constexpr std::size_t lanes = 8;

    class Scalar
    {
    public:
        Scalar() noexcept = default;
        explicit Scalar(const std::uint8_t bytes[encodedSize]) noexcept { fromBytes(bytes); }
        explicit Scalar(PRNG& prng) noexcept { randomize(prng); }

        void randomize(PRNG& prng) noexcept;
        void fromBytes(const std::uint8_t bytes[encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[encodedSize]) const noexcept;

        static constexpr std::size_t size = encodedSize;

    private:
        sc25519 mValue{};
        friend class Point;
        friend class Point8;
    };

    class Point
    {
    public:
        Point() noexcept;
        explicit Point(PRNG& prng);

        static Point mulGenerator(const Scalar& scalar) noexcept;
        static Point fromUniformBytes(const std::uint8_t uniform[uniformSize]) noexcept;
        static Point fromHash(const std::uint8_t uniform[uniformSize]) noexcept
        {
            return fromUniformBytes(uniform);
        }
        static Point fromHash(RandomOracle hash)
        {
            std::array<std::uint8_t, uniformSize> uniform;
            hash.Final(uniform);
            return fromUniformBytes(uniform.data());
        }

        Point mul(const Scalar& scalar) const noexcept;
        Point operator*(const Scalar& scalar) const noexcept { return mul(scalar); }
        Point operator+(const Point& rhs) const noexcept;
        Point operator-(const Point& rhs) const noexcept;
        Point doubled() const noexcept;
        Point& operator+=(const Point& rhs) noexcept { return *this = *this + rhs; }
        Point& operator-=(const Point& rhs) noexcept { return *this = *this - rhs; }
        Point& operator*=(const Scalar& scalar) noexcept { return *this = mul(scalar); }

        bool fromBytes(const std::uint8_t bytes[encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[encodedSize]) const noexcept;
        std::size_t sizeBytes() const noexcept { return encodedSize; }
        bool operator==(const Point& rhs) const noexcept;
        bool operator!=(const Point& rhs) const noexcept { return !(*this == rhs); }

        static constexpr std::size_t size = encodedSize;
        static constexpr std::size_t fromHashLength = uniformSize;

    private:
        struct Uninitialized {};
        explicit Point(Uninitialized) noexcept {}
        ge25519 mValue;
        friend class Point8;
    };

    inline Point operator*(const Scalar& scalar, const Point& point) noexcept
    {
        return point.mul(scalar);
    }

    class Point8
    {
    public:
        Point8() noexcept;
        static Point8 broadcast(const Point& point) noexcept;
        static Point8 fromUniformBytes(
            const std::uint8_t uniform[lanes * uniformSize]) noexcept;
        static Point8 mulGenerator(const std::array<Scalar, lanes>& scalars) noexcept;
        Point8 mul(const Scalar& scalar) const noexcept;
        Point8 mul(const std::array<Scalar, lanes>& scalars) const noexcept;
        Point8 operator+(const Point8& rhs) const noexcept;
        Point8 operator-(const Point8& rhs) const noexcept;
        Point8 doubled() const noexcept;
        void conditionalMove(const Point8& source,
                             const std::array<std::uint8_t, lanes>& select) noexcept;
        bool fromBytes(const std::uint8_t bytes[lanes * encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[lanes * encodedSize]) const noexcept;

    private:
        struct Uninitialized {};
        explicit Point8(Uninitialized) noexcept {}
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x mValue;
#else
        ge4x mValue[2];
#endif
    };
}
}

namespace osuCrypto
{
    template<>
    struct Hashable<Ristretto255::Point, void> : std::true_type
    {
        template<typename Hasher>
        static void hash(const Ristretto255::Point& point, Hasher& hasher)
        {
            std::uint8_t encoded[Ristretto255::encodedSize];
            point.toBytes(encoded);
            hasher.Update(encoded, sizeof(encoded));
        }
    };

    template<>
    struct Hashable<Ristretto255::Point8, void> : std::true_type
    {
        template<typename Hasher>
        static void hash(const Ristretto255::Point8& points, Hasher& hasher)
        {
            std::uint8_t encoded[Ristretto255::lanes * Ristretto255::encodedSize];
            points.toBytes(encoded);
            hasher.Update(encoded, sizeof(encoded));
        }
    };
}
