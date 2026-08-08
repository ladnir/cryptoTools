#include <cryptoTools/Crypto/Edwards25519/Curve25519Backend.h>

#ifdef CRYPTOTOOLS_EDWARDS25519_BACKEND_RELIC

#include <algorithm>
#include <stdexcept>

extern "C" {
#include <cryptoTools/Crypto/Edwards25519/fe25519.h>
#include <cryptoTools/Crypto/Edwards25519/ge25519.h>
}

namespace osuCrypto
{
namespace details
{
namespace curve25519
{
    static_assert(FP_PRIME == 255,
        "The RELIC Edwards25519 backend requires RELIC configured with FP_PRIME=255");

    namespace
    {
        void scalarToBn(bn_t scalar, const Edwards25519::Scalar& value)
        {
            std::uint8_t little[32], big[32];
            value.toBytes(little);
            std::reverse_copy(little, little + 32, big);
            bn_read_bin(scalar, big, sizeof(big));
        }

        void fieldToRelic(fp_t output, const fe25519& input)
        {
            std::uint8_t little[32], big[32];
            fe25519 value = input;
            fe25519_pack(little, &value);
            std::reverse_copy(little, little + 32, big);
            fp_read_bin(output, big, sizeof(big));
        }

        void relicFieldToLittle(std::uint8_t output[32], const fp_t input)
        {
            std::uint8_t big[32];
            fp_write_bin(big, sizeof(big), input);
            std::reverse_copy(big, big + 32, output);
        }
    }

    void RelicEdwardsPoint::init()
    {
        if (core_get() == nullptr)
        {
            if (core_init() != RLC_OK)
                throw std::runtime_error("RELIC core initialization failed");
        }
        if (ed_param_get() != CURVE_ED25519)
            ed_param_set(CURVE_ED25519);
    }

    RelicEdwardsPoint::RelicEdwardsPoint()
    {
        init();
        ed_null(mValue);
        ed_new(mValue);
        ed_set_infty(mValue);
    }

    RelicEdwardsPoint::RelicEdwardsPoint(const RelicEdwardsPoint& other)
    {
        init();
        ed_null(mValue);
        ed_new(mValue);
        ed_copy(mValue, other.mValue);
    }

    RelicEdwardsPoint& RelicEdwardsPoint::operator=(const RelicEdwardsPoint& other)
    {
        if (this != &other)
        {
            init();
            ed_copy(mValue, other.mValue);
        }
        return *this;
    }

    RelicEdwardsPoint::~RelicEdwardsPoint()
    {
        ed_free(mValue);
    }

    RelicEdwardsPoint RelicEdwardsPoint::mulGenerator(
        const Edwards25519::Scalar& scalar)
    {
        init();
        RelicEdwardsPoint result;
        bn_t value;
        bn_null(value);
        bn_new(value);
        scalarToBn(value, scalar);
        ed_mul_gen(result.mValue, value);
        bn_free(value);
        return result;
    }

    RelicEdwardsPoint RelicEdwardsPoint::hashToCurveElligator2(
        const std::uint8_t* message, std::size_t messageSize,
        const std::uint8_t* domain, std::size_t domainSize)
    {
        const auto canonical = Edwards25519::Point::hashToCurveElligator2(
            message, messageSize, domain, domainSize);
        std::uint8_t encoded[size];
        canonical.toBytes(encoded);
        RelicEdwardsPoint result;
        if (!result.fromBytes(encoded))
            throw std::runtime_error("RELIC rejected a canonical Edwards25519 point");
        return result;
    }

    RelicEdwardsPoint RelicEdwardsPoint::mul(
        const Edwards25519::Scalar& scalar) const
    {
        init();
        RelicEdwardsPoint result;
        bn_t value;
        bn_null(value);
        bn_new(value);
        scalarToBn(value, scalar);
        ed_mul(result.mValue, mValue, value);
        bn_free(value);
        return result;
    }

    RelicEdwardsPoint RelicEdwardsPoint::operator+(
        const RelicEdwardsPoint& rhs) const
    {
        init();
        RelicEdwardsPoint result;
        ed_add(result.mValue, mValue, rhs.mValue);
        return result;
    }

    RelicEdwardsPoint RelicEdwardsPoint::operator-(
        const RelicEdwardsPoint& rhs) const
    {
        init();
        RelicEdwardsPoint result;
        ed_sub(result.mValue, mValue, rhs.mValue);
        return result;
    }

    RelicEdwardsPoint RelicEdwardsPoint::doubled() const
    {
        init();
        RelicEdwardsPoint result;
        ed_dbl(result.mValue, mValue);
        return result;
    }

    bool RelicEdwardsPoint::fromBytes(const std::uint8_t bytes[size])
    {
        init();
        ge25519 decoded;
        if (ge25519_unpack_vartime(&decoded, bytes) != 0)
            return false;

        fe25519 inverseZ, x, y;
        fe25519_invert(&inverseZ, &decoded.z);
        fe25519_mul(&x, &decoded.x, &inverseZ);
        fe25519_mul(&y, &decoded.y, &inverseZ);
        fieldToRelic(mValue->x, x);
        fieldToRelic(mValue->y, y);
        fp_set_dig(mValue->z, 1);
#if ED_ADD == EXTND || !defined(STRIP)
        fp_mul(mValue->t, mValue->x, mValue->y);
#endif
        mValue->coord = BASIC;
        return ed_on_curve(mValue) != 0;
    }

    void RelicEdwardsPoint::toBytes(std::uint8_t bytes[size]) const
    {
        init();
        ed_t normalized;
        ed_null(normalized);
        ed_new(normalized);
        ed_norm(normalized, mValue);
        relicFieldToLittle(bytes, normalized->y);
        std::uint8_t x[32];
        relicFieldToLittle(x, normalized->x);
        bytes[31] = static_cast<std::uint8_t>(
            bytes[31] | ((x[0] & 1) << 7));
        ed_free(normalized);
    }

    bool RelicEdwardsPoint::isNeutral() const
    {
        init();
        return ed_is_infty(mValue) != 0;
    }
}
}
}

#endif
