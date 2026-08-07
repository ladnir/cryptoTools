#include "Edwards25519.h"

namespace osuCrypto
{
namespace Edwards25519
{
    void Scalar::fromBytes(const std::uint8_t bytes[encodedSize]) noexcept
    {
        sc25519_from32bytes(&mValue, bytes);
    }

    void Scalar::toBytes(std::uint8_t bytes[encodedSize]) const noexcept
    {
        sc25519_to32bytes(bytes, &mValue);
    }

    Point::Point() noexcept
    {
        ge25519_setneutral(&mValue);
    }

    Point Point::mulGenerator(const Scalar& scalar) noexcept
    {
        Point r;
        ge25519_scalarmult_base(&r.mValue, &scalar.mValue);
        return r;
    }

    Point Point::mul(const Scalar& scalar) const noexcept
    {
        Point r;
        ge25519 p = mValue;
        ge25519_scalarmult(&r.mValue, &p, &scalar.mValue);
        return r;
    }

    Point Point::operator+(const Point& rhs) const noexcept
    {
        Point r;
        ge25519_add(&r.mValue, &mValue, &rhs.mValue);
        return r;
    }

    Point Point::operator-(const Point& rhs) const noexcept
    {
        Point r;
        ge25519_subtract(&r.mValue, &mValue, &rhs.mValue);
        return r;
    }

    Point Point::doubled() const noexcept
    {
        Point r;
        ge25519_double(&r.mValue, &mValue);
        return r;
    }

    bool Point::fromBytes(const std::uint8_t bytes[encodedSize]) noexcept
    {
        return ge25519_unpack_vartime(&mValue, bytes) == 0;
    }

    void Point::toBytes(std::uint8_t bytes[encodedSize]) const noexcept
    {
        ge25519_pack(bytes, &mValue);
    }

    bool Point::isNeutral() const noexcept
    {
        return ge25519_isneutral_vartime(&mValue) != 0;
    }

    Point4::Point4() noexcept
    {
        ge4x_setneutral(&mValue);
    }

    Point4 Point4::broadcast(const Point& point) noexcept
    {
        Point4 r;
        ge4x_from_ge25519(&r.mValue, &point.mValue);
        return r;
    }

    Point4 Point4::mulGenerator(const std::array<Scalar, lanes>& scalars) noexcept
    {
        Point4 r;
        sc25519 s[lanes];
        for (std::size_t i = 0; i != lanes; ++i)
            s[i] = scalars[i].mValue;
        ge4x_scalarsmults_base(&r.mValue, s);
        return r;
    }

    Point4 Point4::mul(const Scalar& scalar) const noexcept
    {
        Point4 r;
        ge4x p = mValue;
        ge4x_scalarmults(&r.mValue, &p, &scalar.mValue);
        return r;
    }

    Point4 Point4::mul(const std::array<Scalar, lanes>& scalars) const noexcept
    {
        Point4 r;
        ge4x p = mValue;
        sc25519 s[lanes];
        for (std::size_t i = 0; i != lanes; ++i)
            s[i] = scalars[i].mValue;
        ge4x_scalarsmults(&r.mValue, &p, s);
        return r;
    }

    Point4 Point4::operator+(const Point4& rhs) const noexcept
    {
        Point4 r;
        ge4x_add(&r.mValue, &mValue, &rhs.mValue);
        return r;
    }

    Point4 Point4::operator-(const Point4& rhs) const noexcept
    {
        Point4 r;
        ge4x_sub(&r.mValue, &mValue, &rhs.mValue);
        return r;
    }

    Point4 Point4::doubled() const noexcept
    {
        Point4 r;
        ge4x_double(&r.mValue, &mValue);
        return r;
    }

    void Point4::conditionalMove(const Point4& source,
                                 const std::array<std::uint8_t, lanes>& select) noexcept
    {
        auto bits = select;
        ge4x_cmovs(&mValue, &source.mValue, bits.data());
    }

    bool Point4::fromBytes(const std::uint8_t bytes[lanes * encodedSize]) noexcept
    {
        std::array<std::uint8_t, lanes * encodedSize> copy;
        for (std::size_t i = 0; i != copy.size(); ++i)
            copy[i] = bytes[i];
        return ge4x_unpack_vartime(&mValue, copy.data()) == 0;
    }

    void Point4::toBytes(std::uint8_t bytes[lanes * encodedSize]) const noexcept
    {
        ge4x_pack(bytes, &mValue);
    }
}
}
