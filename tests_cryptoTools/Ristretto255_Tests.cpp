#include "tests_cryptoTools/Ristretto255_Tests.h"

#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Crypto/Edwards25519/Ristretto255.h>

#include <array>
#include <cstring>

namespace
{
    std::array<unsigned char, 32> fromHex(const char* hex)
    {
        std::array<unsigned char, 32> result{};
        for (std::size_t i = 0; i != result.size(); ++i)
        {
            const auto digit = [](char c) -> unsigned char {
                return static_cast<unsigned char>(c <= '9' ? c - '0' : c - 'a' + 10);
            };
            result[i] = static_cast<unsigned char>(digit(hex[2 * i]) * 16 + digit(hex[2 * i + 1]));
        }
        return result;
    }
}

namespace tests_cryptoTools
{
    void Ristretto255_Test()
    {
        using namespace osuCrypto::Ristretto255;

        unsigned char one[32]{};
        one[0] = 1;
        const Scalar scalarOne(one);
        const auto base = Point::mulGenerator(scalarOne);
        unsigned char encoded[32];
        base.toBytes(encoded);
        const auto expectedBase = fromHex(
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76");
        if (std::memcmp(encoded, expectedBase.data(), sizeof(encoded)) != 0)
            throw osuCrypto::UnitTestFail("Ristretto255 basepoint encoding mismatch");

        unsigned char two[32]{};
        two[0] = 2;
        const auto twice = Point::mulGenerator(Scalar(two));
        twice.toBytes(encoded);
        const auto expectedTwice = fromHex(
            "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919");
        if (std::memcmp(encoded, expectedTwice.data(), sizeof(encoded)) != 0)
            throw osuCrypto::UnitTestFail("Ristretto255 doubled-base encoding mismatch");

        Point decoded;
        if (!decoded.fromBytes(expectedBase.data()) || decoded != base)
            throw osuCrypto::UnitTestFail("Ristretto255 canonical decode mismatch");

        const char* invalid[] = {
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"};
        for (const auto* value : invalid)
        {
            if (decoded.fromBytes(fromHex(value).data()))
                throw osuCrypto::UnitTestFail("Ristretto255 accepted an invalid encoding");
            if (decoded != base)
                throw osuCrypto::UnitTestFail(
                    "failed Ristretto255 decode changed the destination");
        }

        std::array<unsigned char, lanes * uniformSize> uniform;
        for (std::size_t i = 0; i != uniform.size(); ++i)
            uniform[i] = static_cast<unsigned char>(i * 29 + 7);
        auto batch = Point8::fromUniformBytes(uniform.data());
        std::array<unsigned char, lanes * encodedSize> batchEncoded;
        batch.toBytes(batchEncoded.data());
        for (std::size_t lane = 0; lane != lanes; ++lane)
        {
            const auto point = Point::fromUniformBytes(uniform.data() + lane * uniformSize);
            point.toBytes(encoded);
            if (std::memcmp(encoded, batchEncoded.data() + lane * encodedSize, encodedSize) != 0)
                throw osuCrypto::UnitTestFail("Ristretto255 eight-lane uniform map mismatch");
        }
        Point8 decodedBatch;
        if (!decodedBatch.fromBytes(batchEncoded.data()))
            throw osuCrypto::UnitTestFail("Ristretto255 eight-lane decode failed");
        std::array<unsigned char, lanes * encodedSize> roundtrip;
        decodedBatch.toBytes(roundtrip.data());
        if (roundtrip != batchEncoded)
            throw osuCrypto::UnitTestFail("Ristretto255 eight-lane round trip mismatch");

        std::uint64_t state = 0xbb67ae8584caa73bULL;
        for (std::size_t iteration = 0; iteration != 64; ++iteration)
        {
            for (auto& byte : uniform)
            {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                byte = static_cast<unsigned char>(state);
            }
            batch = Point8::fromUniformBytes(uniform.data());
            batch.toBytes(batchEncoded.data());
            for (std::size_t lane = 0; lane != lanes; ++lane)
            {
                Point::fromUniformBytes(uniform.data() + lane * uniformSize)
                    .toBytes(encoded);
                if (std::memcmp(encoded,
                        batchEncoded.data() + lane * encodedSize,
                        encodedSize) != 0)
                    throw osuCrypto::UnitTestFail(
                        "randomized Ristretto255 uniform map mismatch");
            }
            if (!decodedBatch.fromBytes(batchEncoded.data()))
                throw osuCrypto::UnitTestFail(
                    "randomized Ristretto255 batch decode failed");
            decodedBatch.toBytes(roundtrip.data());
            if (roundtrip != batchEncoded)
                throw osuCrypto::UnitTestFail(
                    "randomized Ristretto255 batch codec mismatch");
        }

        // Regression: scalar radix-51 representatives produced by Ristretto
        // decoding are not necessarily carry-normalized. Broadcasting must
        // canonicalize before the IFMA radix-52 conversion.
        const auto broadcastPointBytes = fromHex(
            "0ae4e12d4459dbf21c9a38eb7ebfe76ce7d18190aa483d359873dc75acd98f20");
        const auto broadcastScalarBytes = fromHex(
            "7638ba1f2ba2eefa8d4f254b88b1fa24589869fb4a7ec30104564c717b1a2b0f");
        Point broadcastPoint;
        if (!broadcastPoint.fromBytes(broadcastPointBytes.data()))
            throw osuCrypto::UnitTestFail("Ristretto255 broadcast regression input failed");
        const Scalar broadcastScalar(broadcastScalarBytes.data());
        std::array<Scalar, lanes> broadcastScalars{};
        broadcastScalars[0] = broadcastScalar;
        Point8::broadcast(broadcastPoint).mul(broadcastScalars).toBytes(roundtrip.data());
        (broadcastPoint * broadcastScalar).toBytes(encoded);
        if (std::memcmp(encoded, roundtrip.data(), encodedSize) != 0)
            throw osuCrypto::UnitTestFail("Ristretto255 batched broadcast multiplication mismatch");

        batch.toBytes(batchEncoded.data());
        decodedBatch = batch;
        for (const auto lane : {std::size_t{3}, std::size_t{6}})
        {
            auto invalidBatch = batchEncoded;
            invalidBatch[lane * encodedSize] |= 1;
            if (decodedBatch.fromBytes(invalidBatch.data()))
                throw osuCrypto::UnitTestFail(
                    "Ristretto255 accepted an invalid batch lane");
            decodedBatch.toBytes(roundtrip.data());
            if (roundtrip != batchEncoded)
                throw osuCrypto::UnitTestFail(
                    "failed Ristretto255 batch decode changed the destination");
        }

        for (const auto* value : invalid)
        {
            const auto invalidEncoding = fromHex(value);
            for (const auto lane : {
                    std::size_t{0}, std::size_t{3},
                    std::size_t{4}, std::size_t{7}})
            {
                auto invalidBatch = batchEncoded;
                std::memcpy(invalidBatch.data() + lane * encodedSize,
                    invalidEncoding.data(), encodedSize);
                if (decodedBatch.fromBytes(invalidBatch.data()))
                    throw osuCrypto::UnitTestFail(
                        "Ristretto255 accepted a known-invalid batch encoding");
                decodedBatch.toBytes(roundtrip.data());
                if (roundtrip != batchEncoded)
                    throw osuCrypto::UnitTestFail(
                        "known-invalid batch decode changed the destination");
            }
        }

        for (std::size_t iteration = 0; iteration != 32; ++iteration)
        {
            std::array<Scalar, lanes> randomScalars;
            for (std::size_t lane = 0; lane != lanes; ++lane)
            {
                std::array<unsigned char, encodedSize> bytes;
                for (auto& byte : bytes)
                {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    byte = static_cast<unsigned char>(state);
                }
                randomScalars[lane].fromBytes(bytes.data());
            }
            Point8::mulGenerator(randomScalars).toBytes(roundtrip.data());
            for (std::size_t lane = 0; lane != lanes; ++lane)
            {
                Point::mulGenerator(randomScalars[lane]).toBytes(encoded);
                if (std::memcmp(
                        encoded, roundtrip.data() + lane * encodedSize,
                        encodedSize) != 0)
                    throw osuCrypto::UnitTestFail(
                        "randomized Ristretto255 batch differential mismatch");
            }
        }

        const unsigned char order[32] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
        Scalar reduced(order);
        reduced.toBytes(encoded);
        unsigned char accumulated = 0;
        for (auto byte : encoded) accumulated |= byte;
        if (accumulated != 0)
            throw osuCrypto::UnitTestFail("Ristretto255 scalar reduction mismatch");
    }
}
