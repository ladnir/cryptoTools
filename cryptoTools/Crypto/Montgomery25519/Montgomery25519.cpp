#include "Montgomery25519.h"

#include "portable/montgomery25519_ref.h"

#include <cstring>
#include <stdexcept>

#ifdef SODIUM_MONTGOMERY
#include <sodium.h>
#endif

#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
extern "C" {
#include <cryptoTools/Crypto/Edwards25519/ifma/ge8x_ifma.h>
}
#endif

#ifdef CRYPTOTOOLS_EDWARDS25519_ASM
#include "asm/montgomery25519_asm.h"
#endif

namespace osuCrypto
{
namespace Montgomery25519
{
    namespace
    {
        bool scalarMult(std::uint8_t output[encodedSize],
                        const std::uint8_t scalar[encodedSize],
                        const std::uint8_t point[encodedSize]) noexcept
        {
#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA)
            if (osuCrypto_montgomery25519_has_small_order_ref(point))
                return false;
            alignas(64) std::uint8_t points[lanes * encodedSize];
            alignas(64) std::uint8_t results[lanes * encodedSize];
            for (std::size_t lane = 0; lane != lanes; ++lane)
                std::memcpy(points + lane * encodedSize, point, encodedSize);
            const auto valid = montgomery25519_ifma_scalarmult(
                results, points, scalar);
            std::memcpy(output, results, encodedSize);
            return valid == 0xff;
#elif defined(CRYPTOTOOLS_EDWARDS25519_ASM)
            if (osuCrypto_montgomery25519_has_small_order_ref(point))
                return false;
            alignas(32) std::uint8_t points[4 * encodedSize];
            alignas(32) std::uint8_t results[4 * encodedSize];
            for (std::size_t lane = 0; lane != 4; ++lane)
                std::memcpy(points + lane * encodedSize, point, encodedSize);
            const auto valid = montgomery25519_asm4_scalarmult(
                results, points, scalar);
            std::memcpy(output, results, encodedSize);
            return valid == 0x0f;
#elif defined(SODIUM_MONTGOMERY)
            return crypto_scalarmult_noclamp(output, scalar, point) == 0;
#else
            return osuCrypto_montgomery25519_scalarmult_ref(
                output, scalar, point) == 0;
#endif
        }

        bool batchMult(
            std::uint8_t output[lanes * encodedSize],
            const std::uint8_t points[lanes * encodedSize],
            const std::array<Scalar, lanes>& scalars) noexcept
        {
#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA)
            alignas(64) std::uint8_t scalarBytes[lanes * encodedSize];
            for (std::size_t lane = 0; lane != lanes; ++lane)
            {
                if (osuCrypto_montgomery25519_has_small_order_ref(
                        points + lane * encodedSize))
                    return false;
                scalars[lane].toBytes(scalarBytes + lane * encodedSize);
            }
            return montgomery25519_ifma_scalarsmults(
                output, points, scalarBytes) == 0xff;
#elif defined(CRYPTOTOOLS_EDWARDS25519_ASM)
            alignas(32) std::uint8_t scalarBytes[lanes * encodedSize];
            for (std::size_t lane = 0; lane != lanes; ++lane)
            {
                if (osuCrypto_montgomery25519_has_small_order_ref(
                        points + lane * encodedSize))
                    return false;
                scalars[lane].toBytes(scalarBytes + lane * encodedSize);
            }
            return montgomery25519_asm8_scalarsmults(
                output, points, scalarBytes) == 0xff;
#else
            for (std::size_t lane = 0; lane != lanes; ++lane)
            {
                std::uint8_t scalar[encodedSize];
                scalars[lane].toBytes(scalar);
#ifdef SODIUM_MONTGOMERY
                if (crypto_scalarmult_noclamp(
                        output + lane * encodedSize, scalar,
                        points + lane * encodedSize) != 0)
                    return false;
#else
                if (osuCrypto_montgomery25519_scalarmult_ref(
                        output + lane * encodedSize, scalar,
                        points + lane * encodedSize) != 0)
                    return false;
#endif
            }
            return true;
#endif
        }
    }

    Scalar::Scalar(const std::uint8_t bytes[encodedSize]) noexcept
    {
        fromBytes(bytes);
    }

    Scalar::Scalar(PRNG& prng) noexcept
    {
        randomize(prng);
    }

    void Scalar::randomize(PRNG& prng) noexcept
    {
        prng.get(mBytes.data(), mBytes.size());
        mBytes.back() &= 0x7f;
    }

    void Scalar::fromBytes(const std::uint8_t bytes[encodedSize]) noexcept
    {
        std::memcpy(mBytes.data(), bytes, mBytes.size());
        mBytes.back() &= 0x7f;
    }

    void Scalar::toBytes(std::uint8_t bytes[encodedSize]) const noexcept
    {
        std::memcpy(bytes, mBytes.data(), mBytes.size());
    }

    Point::Point(const std::uint8_t bytes[encodedSize]) noexcept
    {
        (void)fromBytes(bytes);
    }

    Point Point::fromU(std::uint8_t u) noexcept
    {
        Point result;
        result.mBytes[0] = u;
        return result;
    }

    bool Point::fromBytes(const std::uint8_t bytes[encodedSize]) noexcept
    {
        std::memcpy(mBytes.data(), bytes, mBytes.size());
        mBytes.back() &= 0x7f;
        return true;
    }

    void Point::toBytes(std::uint8_t bytes[encodedSize]) const noexcept
    {
        std::memcpy(bytes, mBytes.data(), mBytes.size());
    }

    bool Point::tryMul(const Scalar& scalar, Point& result) const noexcept
    {
        return scalarMult(result.mBytes.data(), scalar.mBytes.data(),
                          mBytes.data());
    }

    Point Point::mul(const Scalar& scalar) const
    {
        Point result;
        if (!tryMul(scalar, result))
            throw std::runtime_error(
                "Montgomery25519 multiplication rejected its input");
        return result;
    }

    bool Point::operator==(const Point& rhs) const noexcept
    {
        std::uint8_t difference = 0;
        for (std::size_t i = 0; i != encodedSize; ++i)
            difference |= mBytes[i] ^ rhs.mBytes[i];
        return difference == 0;
    }

    const Point Point::primeSubgroupGenerator = Point::fromU(9);
    const Point Point::primeTwistSubgroupGenerator = Point::fromU(2);
    const Point Point::wholeGroupGenerator = Point::fromU(6);
    const Point Point::wholeTwistGroupGenerator = Point::fromU(3);

    Point8 Point8::broadcast(const Point& point) noexcept
    {
        Point8 result;
        for (std::size_t lane = 0; lane != lanes; ++lane)
            std::memcpy(result.mBytes.data() + lane * encodedSize,
                        point.mBytes.data(), encodedSize);
        return result;
    }

    Point8 Point8::fromPoints(
        const std::array<Point, lanes>& points) noexcept
    {
        Point8 result;
        for (std::size_t lane = 0; lane != lanes; ++lane)
            std::memcpy(result.mBytes.data() + lane * encodedSize,
                        points[lane].mBytes.data(), encodedSize);
        return result;
    }

    bool Point8::fromBytes(
        const std::uint8_t bytes[lanes * encodedSize]) noexcept
    {
        for (std::size_t lane = 0; lane != lanes; ++lane)
        {
            std::memcpy(mBytes.data() + lane * encodedSize,
                        bytes + lane * encodedSize, encodedSize);
            mBytes[(lane + 1) * encodedSize - 1] &= 0x7f;
        }
        return true;
    }

    void Point8::toBytes(
        std::uint8_t bytes[lanes * encodedSize]) const noexcept
    {
        std::memcpy(bytes, mBytes.data(), mBytes.size());
    }

    bool Point8::tryMul(const Scalar& scalar, Point8& result) const noexcept
    {
#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA)
        std::uint8_t scalarBytes[encodedSize];
        scalar.toBytes(scalarBytes);
        for (std::size_t lane = 0; lane != lanes; ++lane)
            if (osuCrypto_montgomery25519_has_small_order_ref(
                    mBytes.data() + lane * encodedSize))
                return false;
        return montgomery25519_ifma_scalarmult(
            result.mBytes.data(), mBytes.data(), scalarBytes) == 0xff;
#elif defined(CRYPTOTOOLS_EDWARDS25519_ASM)
        std::uint8_t scalarBytes[encodedSize];
        scalar.toBytes(scalarBytes);
        for (std::size_t lane = 0; lane != lanes; ++lane)
            if (osuCrypto_montgomery25519_has_small_order_ref(
                    mBytes.data() + lane * encodedSize))
                return false;
        return montgomery25519_asm8_scalarmult(
            result.mBytes.data(), mBytes.data(), scalarBytes) == 0xff;
#else
        std::array<Scalar, lanes> scalars;
        scalars.fill(scalar);
        return batchMult(result.mBytes.data(), mBytes.data(), scalars);
#endif
    }

    bool Point8::tryMul(const std::array<Scalar, lanes>& scalars,
                        Point8& result) const noexcept
    {
        return batchMult(result.mBytes.data(), mBytes.data(), scalars);
    }

    Point8 Point8::mul(const Scalar& scalar) const
    {
        Point8 result;
        if (!tryMul(scalar, result))
            throw std::runtime_error(
                "Montgomery25519 batch multiplication rejected an input");
        return result;
    }

    Point8 Point8::mul(const std::array<Scalar, lanes>& scalars) const
    {
        Point8 result;
        if (!tryMul(scalars, result))
            throw std::runtime_error(
                "Montgomery25519 batch multiplication rejected an input");
        return result;
    }

    void Backend::init() noexcept
    {
#if defined(SODIUM_MONTGOMERY) && \
    !defined(CRYPTOTOOLS_EDWARDS25519_IFMA) && \
    !defined(CRYPTOTOOLS_EDWARDS25519_ASM)
        const int initialized = sodium_init();
        (void)initialized;
#endif
    }
}
}
