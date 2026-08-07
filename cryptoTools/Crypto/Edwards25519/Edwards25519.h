#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

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
}
