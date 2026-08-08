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
    constexpr std::size_t lanes = 8;

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
        friend class Point8;
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
        friend class Point8;
    };

    // A fixed eight-point batch. The current backend is two independent
    // four-lane blocks; AVX-512 IFMA can replace this private representation
    // without changing consumers.
    class Point8
    {
    public:
        Point8() noexcept;

        static Point8 broadcast(const Point& point) noexcept;
        // Hash eight equal-length, lane-major messages.
        static Point8 hashToCurveElligator2(
            const std::uint8_t* messages, std::size_t messageSize,
            const std::uint8_t* domain, std::size_t domainSize);
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
        ge4x mValue[2];
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
struct Hashable<Edwards25519::Point8, void> : std::true_type
{
    template<typename Hasher>
    static void hash(const Edwards25519::Point8& points, Hasher& hasher)
    {
        std::uint8_t encoded[Edwards25519::lanes * Edwards25519::encodedSize];
        points.toBytes(encoded);
        hasher.Update(encoded, Edwards25519::lanes * Edwards25519::encodedSize);
    }
};
}
