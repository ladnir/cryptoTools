#include "Edwards25519.h"

#include <cryptoTools/Crypto/Blake2.h>

#include <array>
#include <limits>
#include <stdexcept>

namespace
{
    constexpr std::size_t xmdBlockSize = 128;
    constexpr std::size_t xmdDigestSize = 64;
    constexpr std::size_t fieldElementWideSize = 48;
    constexpr std::size_t hashToFieldSize = 2 * fieldElementWideSize;
    constexpr char suitePrefix[] = "cryptoTools-v1-";
    constexpr char suiteSuffix[] =
        "-edwards25519_XMD:BLAKE2B_ELL2_RO_";
    constexpr std::size_t suiteOverhead =
        sizeof(suitePrefix) + sizeof(suiteSuffix) - 2;

    void updateByte(osuCrypto::Blake2& hash, std::uint8_t value)
    {
        hash.Update(&value, 1);
    }

    std::array<std::uint8_t, hashToFieldSize> expandMessageXmdBlake2b(
        const std::uint8_t* message, std::size_t messageSize,
        const std::uint8_t* domain, std::size_t domainSize)
    {
        if ((messageSize && message == nullptr) ||
            domain == nullptr || domainSize == 0 ||
            domainSize > 255 - suiteOverhead)
            throw std::invalid_argument(
                "Edwards25519 Elligator2 domain is empty or too long");

        std::array<std::uint8_t, xmdBlockSize> zeroPad{};
        std::array<std::uint8_t, xmdDigestSize> b0{};
        std::array<std::uint8_t, xmdDigestSize> b1{};
        std::array<std::uint8_t, xmdDigestSize> b2{};
        const std::uint8_t outputLength[2] = {
            static_cast<std::uint8_t>(hashToFieldSize >> 8),
            static_cast<std::uint8_t>(hashToFieldSize)};
        const auto domainLength = static_cast<std::uint8_t>(
            domainSize + suiteOverhead);
        const auto updateDomain = [&](osuCrypto::Blake2& h) {
            h.Update(suitePrefix, sizeof(suitePrefix) - 1);
            h.Update(domain, domainSize);
            h.Update(suiteSuffix, sizeof(suiteSuffix) - 1);
            updateByte(h, domainLength);
        };

        osuCrypto::Blake2 hash(xmdDigestSize);
        hash.Update(zeroPad.data(), zeroPad.size());
        if (messageSize)
            hash.Update(message, messageSize);
        hash.Update(outputLength, sizeof(outputLength));
        updateByte(hash, 0);
        updateDomain(hash);
        hash.Final(b0.data());

        hash.Reset(xmdDigestSize);
        hash.Update(b0.data(), b0.size());
        updateByte(hash, 1);
        updateDomain(hash);
        hash.Final(b1.data());

        for (std::size_t i = 0; i != b0.size(); ++i)
            b0[i] ^= b1[i];
        hash.Reset(xmdDigestSize);
        hash.Update(b0.data(), b0.size());
        updateByte(hash, 2);
        updateDomain(hash);
        hash.Final(b2.data());

        std::array<std::uint8_t, hashToFieldSize> uniform{};
        for (std::size_t i = 0; i != b1.size(); ++i)
            uniform[i] = b1[i];
        for (std::size_t i = 0; i != uniform.size() - b1.size(); ++i)
            uniform[b1.size() + i] = b2[i];
        return uniform;
    }

    std::uint64_t loadBigEndian64(const std::uint8_t* bytes)
    {
        return (static_cast<std::uint64_t>(bytes[0]) << 56) |
               (static_cast<std::uint64_t>(bytes[1]) << 48) |
               (static_cast<std::uint64_t>(bytes[2]) << 40) |
               (static_cast<std::uint64_t>(bytes[3]) << 32) |
               (static_cast<std::uint64_t>(bytes[4]) << 24) |
               (static_cast<std::uint64_t>(bytes[5]) << 16) |
               (static_cast<std::uint64_t>(bytes[6]) << 8) |
               static_cast<std::uint64_t>(bytes[7]);
    }

    fe25519 fieldElementFromWideBytes(const std::uint8_t bytes[fieldElementWideSize])
    {
        // For p = 2^255 - 19, split the 384-bit big-endian input at bit 255
        // and fold the high 129 bits with 2^255 = 19. This avoids 24 general
        // field multiplications for the two hash_to_field elements.
        constexpr std::uint64_t mask51 = (UINT64_C(1) << 51) - 1;
        const std::uint64_t a0 = loadBigEndian64(bytes + 40);
        const std::uint64_t a1 = loadBigEndian64(bytes + 32);
        const std::uint64_t a2 = loadBigEndian64(bytes + 24);
        const std::uint64_t a3 = loadBigEndian64(bytes + 16);
        const std::uint64_t a4 = loadBigEndian64(bytes + 8);
        const std::uint64_t a5 = loadBigEndian64(bytes);

        const std::uint64_t high0 = ((a3 >> 63) | (a4 << 1)) & mask51;
        const std::uint64_t high1 = ((a4 >> 50) | (a5 << 14)) & mask51;
        const std::uint64_t high2 = a5 >> 37;
        fe25519 result = {{
            (a0 & mask51) + 19 * high0,
            (((a0 >> 51) | (a1 << 13)) & mask51) + 19 * high1,
            (((a1 >> 38) | (a2 << 26)) & mask51) + 19 * high2,
            ((a2 >> 25) | (a3 << 39)) & mask51,
            (a3 >> 12) & mask51}};

        std::uint64_t carry;
        carry = result.v[0] >> 51; result.v[0] &= mask51; result.v[1] += carry;
        carry = result.v[1] >> 51; result.v[1] &= mask51; result.v[2] += carry;
        carry = result.v[2] >> 51; result.v[2] &= mask51; result.v[3] += carry;
        carry = result.v[3] >> 51; result.v[3] &= mask51; result.v[4] += carry;
        carry = result.v[4] >> 51; result.v[4] &= mask51; result.v[0] += 19 * carry;
        carry = result.v[0] >> 51; result.v[0] &= mask51; result.v[1] += carry;
        carry = result.v[1] >> 51; result.v[1] &= mask51; result.v[2] += carry;
        carry = result.v[2] >> 51; result.v[2] &= mask51; result.v[3] += carry;
        carry = result.v[3] >> 51; result.v[3] &= mask51; result.v[4] += carry;
        carry = result.v[4] >> 51; result.v[4] &= mask51; result.v[0] += 19 * carry;
        return result;
    }
}

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

    Point Point::hashToCurveElligator2(
        const std::uint8_t* message, std::size_t messageSize,
        const std::uint8_t* domain, std::size_t domainSize)
    {
        const auto uniform = expandMessageXmdBlake2b(
            message, messageSize, domain, domainSize);
        const auto u0 = fieldElementFromWideBytes(uniform.data());
        const auto u1 = fieldElementFromWideBytes(
            uniform.data() + fieldElementWideSize);

        Point q0, q1, result;
        ge25519_map_to_curve_elligator2(&q0.mValue, &u0);
        ge25519_map_to_curve_elligator2(&q1.mValue, &u1);
        ge25519_add(&result.mValue, &q0.mValue, &q1.mValue);
        ge25519_double(&result.mValue, &result.mValue);
        ge25519_double(&result.mValue, &result.mValue);
        ge25519_double(&result.mValue, &result.mValue);
        return result;
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

    Point4 Point4::hashToCurveElligator2(
        const std::uint8_t* messages, std::size_t messageSize,
        const std::uint8_t* domain, std::size_t domainSize)
    {
        if (messageSize && messages == nullptr)
            throw std::invalid_argument(
                "Edwards25519 four-lane messages pointer is null");
        if (messageSize > std::numeric_limits<std::size_t>::max() / lanes)
            throw std::invalid_argument(
                "Edwards25519 four-lane message size overflows");

        std::array<fe25519, lanes> u0;
        std::array<fe25519, lanes> u1;
        for (std::size_t lane = 0; lane != lanes; ++lane)
        {
            const auto* message = messageSize ?
                messages + lane * messageSize : nullptr;
            const auto uniform = expandMessageXmdBlake2b(
                message, messageSize, domain, domainSize);
            u0[lane] = fieldElementFromWideBytes(uniform.data());
            u1[lane] = fieldElementFromWideBytes(
                uniform.data() + fieldElementWideSize);
        }

        Point4 q0, q1, result;
        ge4x_map_to_curve_elligator2(&q0.mValue, u0.data());
        ge4x_map_to_curve_elligator2(&q1.mValue, u1.data());
        ge4x_add(&result.mValue, &q0.mValue, &q1.mValue);
        ge4x_double(&result.mValue, &result.mValue);
        ge4x_double(&result.mValue, &result.mValue);
        ge4x_double(&result.mValue, &result.mValue);
        return result;
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
