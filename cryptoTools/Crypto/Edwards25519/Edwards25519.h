#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <cryptoTools/Crypto/Hashable.h>

extern "C" {
#include <cryptoTools/Crypto/Edwards25519/ge25519.h>
#include <cryptoTools/Crypto/Edwards25519/ge4x.h>
}

namespace osuCrypto
{
namespace Edwards25519
{
    constexpr std::size_t encodedSize = 32;
    constexpr std::size_t lanes = 4;

#ifdef CRYPTOTOOLS_EDWARDS25519_ASM
    constexpr bool hasOptimizedBackend = true;
#else
    constexpr bool hasOptimizedBackend = false;
#endif

    // A clamped scalar reduced modulo the order, matching Simplest OT's
    // historical scalar semantics.
    class Scalar
    {
    public:
        Scalar() noexcept = default;
        explicit Scalar(const std::uint8_t bytes[encodedSize]) noexcept { fromBytes(bytes); }

        void fromBytes(const std::uint8_t bytes[encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[encodedSize]) const noexcept;

    private:
        sc25519 mValue{};
        friend class Point;
        friend class Point4;
    };

    class Point
    {
    public:
        Point() noexcept;

        static Point mulGenerator(const Scalar& scalar) noexcept;
        // A random-oracle hash to the prime-order Edwards25519 subgroup.
        // This is a custom XMD:BLAKE2B_ELL2_RO_ suite using the RFC 9380
        // Elligator2 map and cofactor clearing. The mandatory application
        // domain is wrapped in a versioned cryptoTools suite identifier.
        static Point hashToCurveElligator2(
            const std::uint8_t* message, std::size_t messageSize,
            const std::uint8_t* domain, std::size_t domainSize);
        Point mul(const Scalar& scalar) const noexcept;
        Point operator+(const Point& rhs) const noexcept;
        Point operator-(const Point& rhs) const noexcept;
        Point doubled() const noexcept;

        bool fromBytes(const std::uint8_t bytes[encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[encodedSize]) const noexcept;
        bool isNeutral() const noexcept;

    private:
        ge25519 mValue;
        friend class Point4;
    };

    // A fixed four-point batch. The optimized backend retains the original
    // structure-of-arrays AVX representation; the fallback holds four scalar
    // points. Selection is entirely at compile time.
    class Point4
    {
    public:
        Point4() noexcept;

        static Point4 broadcast(const Point& point) noexcept;
        // Hash four equal-length, lane-major messages. messages contains
        // lane 0 followed by lane 1, lane 2, and lane 3.
        static Point4 hashToCurveElligator2(
            const std::uint8_t* messages, std::size_t messageSize,
            const std::uint8_t* domain, std::size_t domainSize);
        static Point4 mulGenerator(const std::array<Scalar, lanes>& scalars) noexcept;
        Point4 mul(const Scalar& scalar) const noexcept;
        Point4 mul(const std::array<Scalar, lanes>& scalars) const noexcept;
        Point4 operator+(const Point4& rhs) const noexcept;
        Point4 operator-(const Point4& rhs) const noexcept;
        Point4 doubled() const noexcept;
        void conditionalMove(const Point4& source,
                             const std::array<std::uint8_t, lanes>& select) noexcept;

        bool fromBytes(const std::uint8_t bytes[lanes * encodedSize]) noexcept;
        void toBytes(std::uint8_t bytes[lanes * encodedSize]) const noexcept;

    private:
        ge4x mValue;
    };
}

template<>
struct Hashable<Edwards25519::Point, void> : std::true_type
{
    template<typename Hasher>
    static void hash(const Edwards25519::Point& point, Hasher& hasher)
    {
        std::uint8_t encoded[Edwards25519::encodedSize];
        point.toBytes(encoded);
        hasher.Update(encoded, Edwards25519::encodedSize);
    }
};

template<>
struct Hashable<Edwards25519::Point4, void> : std::true_type
{
    template<typename Hasher>
    static void hash(const Edwards25519::Point4& points, Hasher& hasher)
    {
        std::uint8_t encoded[Edwards25519::lanes * Edwards25519::encodedSize];
        points.toBytes(encoded);
        hasher.Update(encoded, Edwards25519::lanes * Edwards25519::encodedSize);
    }
};
}
