#include "Ristretto255.h"

#include <cstring>

namespace osuCrypto
{
namespace Ristretto255
{
    void Scalar::randomize(PRNG& prng) noexcept
    {
        std::uint8_t bytes[encodedSize];
        prng.get(bytes, sizeof(bytes));
        fromBytes(bytes);
    }

    void Scalar::fromBytes(const std::uint8_t bytes[encodedSize]) noexcept
    {
        sc25519_from32bytes_mod_order(&mValue, bytes);
    }

    void Scalar::toBytes(std::uint8_t bytes[encodedSize]) const noexcept
    {
        sc25519_to32bytes(bytes, &mValue);
    }

    Point::Point() noexcept
    {
        ge25519_setneutral(&mValue);
    }

    Point::Point(PRNG& prng)
    {
        std::uint8_t uniform[uniformSize];
        prng.get(uniform, sizeof(uniform));
        osuCrypto_ristretto255_from_uniform(&mValue, uniform);
    }

    Point Point::mulGenerator(const Scalar& scalar) noexcept
    {
        Point r{Uninitialized{}};
        ge25519_scalarmult_base(&r.mValue, &scalar.mValue);
        return r;
    }

    Point Point::fromUniformBytes(const std::uint8_t uniform[uniformSize]) noexcept
    {
        Point r{Uninitialized{}};
        osuCrypto_ristretto255_from_uniform(&r.mValue, uniform);
        return r;
    }

    Point Point::mul(const Scalar& scalar) const noexcept
    {
        Point r{Uninitialized{}};
        ge25519 p = mValue;
        ge25519_scalarmult(&r.mValue, &p, &scalar.mValue);
        return r;
    }

    Point Point::operator+(const Point& rhs) const noexcept
    {
        Point r{Uninitialized{}};
        ge25519_add(&r.mValue, &mValue, &rhs.mValue);
        return r;
    }

    Point Point::operator-(const Point& rhs) const noexcept
    {
        Point r{Uninitialized{}};
        ge25519_subtract(&r.mValue, &mValue, &rhs.mValue);
        return r;
    }

    Point Point::doubled() const noexcept
    {
        Point r{Uninitialized{}};
        ge25519_double(&r.mValue, &mValue);
        return r;
    }

    bool Point::fromBytes(const std::uint8_t bytes[encodedSize]) noexcept
    {
        return osuCrypto_ristretto255_frombytes(&mValue, bytes) == 0;
    }

    void Point::toBytes(std::uint8_t bytes[encodedSize]) const noexcept
    {
        osuCrypto_ristretto255_tobytes(bytes, &mValue);
    }

    bool Point::operator==(const Point& rhs) const noexcept
    {
        std::uint8_t a[encodedSize], b[encodedSize];
        toBytes(a);
        rhs.toBytes(b);
        std::uint8_t difference = 0;
        for (std::size_t i = 0; i != encodedSize; ++i)
            difference |= a[i] ^ b[i];
        return difference == 0;
    }

    Point8::Point8() noexcept
    {
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_setneutral(&mValue);
#else
        ge4x_setneutral(&mValue[0]);
        ge4x_setneutral(&mValue[1]);
#endif
    }

    Point8 Point8::broadcast(const Point& point) noexcept
    {
        Point8 r{Uninitialized{}};
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_from_ge25519(&r.mValue, &point.mValue);
#else
        ge4x_from_ge25519(&r.mValue[0], &point.mValue);
        ge4x_from_ge25519(&r.mValue[1], &point.mValue);
#endif
        return r;
    }

    Point8 Point8::fromUniformBytes(
        const std::uint8_t uniform[lanes * uniformSize]) noexcept
    {
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        Point8 r{Uninitialized{}};
        ge8x_ristretto_from_uniform(&r.mValue, uniform);
        return r;
#else
        ge25519 points[lanes];
        for (std::size_t i = 0; i != lanes; ++i)
            osuCrypto_ristretto255_from_uniform(&points[i], uniform + i * uniformSize);
        Point8 r{Uninitialized{}};
        ge4x_from_ge25519s(&r.mValue[0], points);
        ge4x_from_ge25519s(&r.mValue[1], points + 4);
        return r;
#endif
    }

    Point8 Point8::mulGenerator(const std::array<Scalar, lanes>& scalars) noexcept
    {
        sc25519 s[lanes];
        for (std::size_t i = 0; i != lanes; ++i) s[i] = scalars[i].mValue;
        Point8 r{Uninitialized{}};
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_scalarsmults_base(&r.mValue, s);
#else
        ge4x_scalarsmults_base(&r.mValue[0], s);
        ge4x_scalarsmults_base(&r.mValue[1], s + 4);
#endif
        return r;
    }

    Point8 Point8::mul(const Scalar& scalar) const noexcept
    {
        Point8 r{Uninitialized{}};
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_scalarmult(&r.mValue, &mValue, &scalar.mValue);
#else
        ge4x p0 = mValue[0], p1 = mValue[1];
        ge4x_scalarmults(&r.mValue[0], &p0, &scalar.mValue);
        ge4x_scalarmults(&r.mValue[1], &p1, &scalar.mValue);
#endif
        return r;
    }

    Point8 Point8::mul(const std::array<Scalar, lanes>& scalars) const noexcept
    {
        sc25519 s[lanes];
        for (std::size_t i = 0; i != lanes; ++i) s[i] = scalars[i].mValue;
        Point8 r{Uninitialized{}};
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_scalarsmults(&r.mValue, &mValue, s);
#else
        ge4x p0 = mValue[0], p1 = mValue[1];
        ge4x_scalarsmults(&r.mValue[0], &p0, s);
        ge4x_scalarsmults(&r.mValue[1], &p1, s + 4);
#endif
        return r;
    }

    Point8 Point8::operator+(const Point8& rhs) const noexcept
    {
        Point8 r{Uninitialized{}};
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_add(&r.mValue, &mValue, &rhs.mValue);
#else
        ge4x_add(&r.mValue[0], &mValue[0], &rhs.mValue[0]);
        ge4x_add(&r.mValue[1], &mValue[1], &rhs.mValue[1]);
#endif
        return r;
    }

    Point8 Point8::operator-(const Point8& rhs) const noexcept
    {
        Point8 r{Uninitialized{}};
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_sub(&r.mValue, &mValue, &rhs.mValue);
#else
        ge4x_sub(&r.mValue[0], &mValue[0], &rhs.mValue[0]);
        ge4x_sub(&r.mValue[1], &mValue[1], &rhs.mValue[1]);
#endif
        return r;
    }

    Point8 Point8::doubled() const noexcept
    {
        Point8 r{Uninitialized{}};
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_double(&r.mValue, &mValue);
#else
        ge4x_double(&r.mValue[0], &mValue[0]);
        ge4x_double(&r.mValue[1], &mValue[1]);
#endif
        return r;
    }

    void Point8::conditionalMove(const Point8& source,
        const std::array<std::uint8_t, lanes>& select) noexcept
    {
        auto bits = select;
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_cmovs(&mValue, &source.mValue, bits.data());
#else
        ge4x_cmovs(&mValue[0], &source.mValue[0], bits.data());
        ge4x_cmovs(&mValue[1], &source.mValue[1], bits.data() + 4);
#endif
    }

    bool Point8::fromBytes(const std::uint8_t bytes[lanes * encodedSize]) noexcept
    {
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        return ge8x_ristretto_frombytes(&mValue, bytes) == 0;
#else
        ge25519 points[lanes];
        for (std::size_t i = 0; i != lanes; ++i)
            if (osuCrypto_ristretto255_frombytes(&points[i], bytes + i * encodedSize) != 0)
                return false;
        ge4x_from_ge25519s(&mValue[0], points);
        ge4x_from_ge25519s(&mValue[1], points + 4);
        return true;
#endif
    }

    void Point8::toBytes(std::uint8_t bytes[lanes * encodedSize]) const noexcept
    {
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        ge8x_ristretto_tobytes(bytes, &mValue);
#else
        ge25519 points[lanes];
        ge4x_to_ge25519s(points, &mValue[0]);
        ge4x_to_ge25519s(points + 4, &mValue[1]);
        for (std::size_t i = 0; i != lanes; ++i)
            osuCrypto_ristretto255_tobytes(bytes + i * encodedSize, &points[i]);
#endif
    }
}
}
