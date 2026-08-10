#include "tests_cryptoTools/Montgomery25519_Tests.h"

#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Crypto/Montgomery25519/Montgomery25519.h>
#include <cryptoTools/Crypto/Montgomery25519/portable/montgomery25519_ref.h>

#ifdef SODIUM_MONTGOMERY
#include <sodium.h>
#endif

#include <array>
#include <cstring>

namespace tests_cryptoTools
{
    void Montgomery25519_Test()
    {
        namespace Monty = osuCrypto::Montgomery25519;

        static const std::uint8_t scalar[32] = {
            0x35, 0x4a, 0x67, 0x27, 0x0b, 0x01, 0xff, 0x9e,
            0x25, 0x9c, 0x23, 0x50, 0x56, 0x95, 0x9e, 0x00,
            0x8b, 0x14, 0xbe, 0x2d, 0x05, 0x60, 0xdd, 0x88,
            0xd6, 0x6f, 0xc6, 0x2d, 0x68, 0xf2, 0x7d, 0x35 };
        static const std::uint8_t expected[32] = {
            0x9f, 0x14, 0x91, 0x64, 0xce, 0x15, 0x1d, 0x68,
            0xa0, 0x36, 0x93, 0xf5, 0x3c, 0xb3, 0x34, 0x41,
            0xf7, 0x5b, 0x6a, 0x50, 0xad, 0xc3, 0x9c, 0x01,
            0xc3, 0x52, 0x6f, 0x58, 0xe1, 0x6c, 0xf2, 0x47 };
        std::uint8_t portable[32];
        const auto generator = Monty::Point::wholeGroupGenerator;
        std::uint8_t generatorBytes[32];
        generator.toBytes(generatorBytes);
        if (osuCrypto_montgomery25519_scalarmult_ref(
                portable, scalar, generatorBytes) != 0 ||
            std::memcmp(portable, expected, sizeof(expected)) != 0)
            throw osuCrypto::UnitTestFail(
                "Montgomery25519 portable noclamp vector mismatch");

        std::array<Monty::Scalar, Monty::lanes> scalars;
        std::array<Monty::Point, Monty::lanes> points;
        osuCrypto::PRNG prng(osuCrypto::ZeroBlock);
        for (unsigned round = 0; round != 32; ++round)
        {
            for (std::size_t lane = 0; lane != Monty::lanes; ++lane)
            {
                std::uint8_t pointBytes[32];
                scalars[lane].randomize(prng);
                do {
                    prng.get(pointBytes, sizeof(pointBytes));
                    pointBytes[31] &= 0x7f;
                } while (osuCrypto_montgomery25519_has_small_order_ref(
                    pointBytes));
                points[lane].fromBytes(pointBytes);
            }

            const auto batch = Monty::Point8::fromPoints(points).mul(scalars);
            std::array<std::uint8_t,
                Monty::lanes * Monty::encodedSize> encoded;
            batch.toBytes(encoded.data());
            for (std::size_t lane = 0; lane != Monty::lanes; ++lane)
            {
                std::uint8_t scalarBytes[32], pointBytes[32], reference[32];
                std::uint8_t portableReference[32];
                scalars[lane].toBytes(scalarBytes);
                points[lane].toBytes(pointBytes);
                if (osuCrypto_montgomery25519_scalarmult_ref(
                        portableReference, scalarBytes, pointBytes) != 0)
                    throw osuCrypto::UnitTestFail(
                        "Montgomery25519 portable reference rejected a test input");
#ifdef SODIUM_MONTGOMERY
                if (crypto_scalarmult_noclamp(
                        reference, scalarBytes, pointBytes) != 0)
                    throw osuCrypto::UnitTestFail(
                        "modified libsodium rejected a Montgomery25519 test input");
                if (std::memcmp(reference, portableReference,
                                sizeof(reference)) != 0)
                    throw osuCrypto::UnitTestFail(
                        "Montgomery25519 portable/libsodium mismatch");
#else
                std::memcpy(reference, portableReference, sizeof(reference));
#endif
                if (std::memcmp(reference,
                        encoded.data() + lane * Monty::encodedSize,
                        Monty::encodedSize) != 0)
                    throw osuCrypto::UnitTestFail(
                        "Montgomery25519 batch differential mismatch");
            }

            const auto shared =
                Monty::Point8::fromPoints(points).mul(scalars[0]);
            shared.toBytes(encoded.data());
            std::uint8_t sharedScalar[32];
            scalars[0].toBytes(sharedScalar);
            for (std::size_t lane = 0; lane != Monty::lanes; ++lane)
            {
                std::uint8_t pointBytes[32], reference[32];
                std::uint8_t portableReference[32];
                points[lane].toBytes(pointBytes);
                if (osuCrypto_montgomery25519_scalarmult_ref(
                        portableReference, sharedScalar, pointBytes) != 0)
                    throw osuCrypto::UnitTestFail(
                        "Montgomery25519 shared-scalar reference rejected an input");
#ifdef SODIUM_MONTGOMERY
                if (crypto_scalarmult_noclamp(
                        reference, sharedScalar, pointBytes) != 0 ||
                    std::memcmp(reference, portableReference,
                                sizeof(reference)) != 0)
                    throw osuCrypto::UnitTestFail(
                        "Montgomery25519 shared-scalar libsodium mismatch");
#else
                std::memcpy(reference, portableReference, sizeof(reference));
#endif
                if (std::memcmp(reference,
                        encoded.data() + lane * Monty::encodedSize,
                        Monty::encodedSize) != 0)
                    throw osuCrypto::UnitTestFail(
                        "Montgomery25519 shared-scalar batch mismatch");
            }
        }

        std::uint8_t zero[32]{};
        Monty::Point invalid(zero), result;
        if (invalid.tryMul(scalars[0], result))
            throw osuCrypto::UnitTestFail(
                "Montgomery25519 accepted a small-order point");
    }
}
