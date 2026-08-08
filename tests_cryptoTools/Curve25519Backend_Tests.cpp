#include "tests_cryptoTools/Curve25519Backend_Tests.h"

#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Crypto/Edwards25519/Curve25519Backend.h>

#include <array>
#include <cstring>

namespace tests_cryptoTools
{
    void Curve25519Backend_Test()
    {
        namespace Edwards = osuCrypto::Edwards25519::Backend;
        namespace Ristretto = osuCrypto::Ristretto255::Backend;
        using Implementation = osuCrypto::details::curve25519::Implementation;

#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA)
        static_assert(Edwards::implementation == Implementation::Avx512Ifma);
        static_assert(Ristretto::implementation == Implementation::Avx512Ifma);
#elif defined(CRYPTOTOOLS_EDWARDS25519_ASM)
        static_assert(Edwards::implementation == Implementation::Assembly);
        static_assert(Ristretto::implementation == Implementation::Assembly);
#elif defined(CRYPTOTOOLS_EDWARDS25519_BACKEND_SODIUM)
        static_assert(Edwards::implementation == Implementation::Sodium);
        static_assert(Ristretto::implementation == Implementation::Sodium);
#elif defined(CRYPTOTOOLS_EDWARDS25519_BACKEND_RELIC)
        static_assert(Edwards::implementation == Implementation::Relic);
        static_assert(Ristretto::implementation == Implementation::Portable);
#else
        static_assert(Edwards::implementation == Implementation::Portable);
        static_assert(Ristretto::implementation == Implementation::Portable);
#endif
        static_assert(osuCrypto::Hashable<Edwards::Point>::value);
        static_assert(osuCrypto::Hashable<Edwards::Point8>::value);
        static_assert(osuCrypto::Hashable<Ristretto::Point>::value);
        static_assert(osuCrypto::Hashable<Ristretto::Point8>::value);

        Edwards::init();
        std::uint8_t oneBytes[32]{};
        oneBytes[0] = 1;
        std::uint8_t twoBytes[32]{};
        twoBytes[0] = 2;
        std::uint8_t zeroBytes[32]{};

        const Edwards::Scalar edOne(oneBytes);
        const auto edBase = Edwards::Point::mulGenerator(edOne);
        std::uint8_t encoded[32], expected[32];
        edBase.doubled().toBytes(encoded);
        (edBase + edBase).toBytes(expected);
        if (std::memcmp(encoded, expected, sizeof(encoded)) != 0)
            throw osuCrypto::UnitTestFail("Edwards25519 backend doubling mismatch");

        Edwards::Point edDecoded;
        edBase.toBytes(encoded);
        if (!edDecoded.fromBytes(encoded))
            throw osuCrypto::UnitTestFail("Edwards25519 backend decode failed");

        static constexpr std::uint8_t message[] = { 1, 3, 3, 7 };
        static constexpr std::uint8_t domain[] = "cryptoTools facade test";
        const auto edHash = Edwards::Point::hashToCurveElligator2(
            message, sizeof(message), domain, sizeof(domain) - 1);
        const auto canonicalHash = osuCrypto::Edwards25519::Point::
            hashToCurveElligator2(
                message, sizeof(message), domain, sizeof(domain) - 1);
        edHash.toBytes(encoded);
        canonicalHash.toBytes(expected);
        if (std::memcmp(encoded, expected, sizeof(encoded)) != 0)
            throw osuCrypto::UnitTestFail(
                "Edwards25519 backend hash-to-curve mismatch");

        std::array<Edwards::Scalar, Edwards::lanes> edScalars;
        for (std::size_t i = 0; i != Edwards::lanes; ++i)
            edScalars[i] = Edwards::Scalar(oneBytes);
        auto edBatch = Edwards::Point8::mulGenerator(edScalars);
        std::array<std::uint8_t, Edwards::lanes * Edwards::encodedSize> batchEncoded;
        edBatch.toBytes(batchEncoded.data());
        edBase.toBytes(encoded);
        for (std::size_t i = 0; i != Edwards::lanes; ++i)
            if (std::memcmp(batchEncoded.data() + i * Edwards::encodedSize,
                    encoded, Edwards::encodedSize) != 0)
                throw osuCrypto::UnitTestFail("Edwards25519 backend batch mismatch");

        const Ristretto::Scalar ristOne(oneBytes);
        const Ristretto::Scalar ristTwo(twoBytes);
        const auto ristBase = Ristretto::Point::mulGenerator(ristOne);
        const auto ristTwice = Ristretto::Point::mulGenerator(ristTwo);
        ristBase.doubled().toBytes(encoded);
        ristTwice.toBytes(expected);
        if (std::memcmp(encoded, expected, sizeof(encoded)) != 0)
            throw osuCrypto::UnitTestFail("Ristretto255 backend doubling mismatch");

        Ristretto::Point::mulGenerator(Ristretto::Scalar(zeroBytes)).toBytes(encoded);
        Ristretto::Point{}.toBytes(expected);
        if (std::memcmp(encoded, expected, sizeof(encoded)) != 0)
            throw osuCrypto::UnitTestFail("Ristretto255 backend zero scalar mismatch");

        Ristretto::Point ristDecoded;
        ristBase.toBytes(encoded);
        if (!ristDecoded.fromBytes(encoded))
            throw osuCrypto::UnitTestFail("Ristretto255 backend decode failed");

        std::array<Ristretto::Scalar, Ristretto::lanes> ristScalars;
        for (std::size_t i = 0; i != Ristretto::lanes; ++i)
            ristScalars[i] = Ristretto::Scalar(oneBytes);
        auto ristBatch = Ristretto::Point8::mulGenerator(ristScalars);
        ristBatch.toBytes(batchEncoded.data());
        for (std::size_t i = 0; i != Ristretto::lanes; ++i)
            if (std::memcmp(batchEncoded.data() + i * Ristretto::encodedSize,
                    encoded, Ristretto::encodedSize) != 0)
                throw osuCrypto::UnitTestFail("Ristretto255 backend batch mismatch");
    }
}
