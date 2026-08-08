#include "tests_cryptoTools/Edwards25519_Tests.h"

#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Crypto/Blake2.h>
#include <cryptoTools/Crypto/Edwards25519/Edwards25519.h>

#include <array>
#include <cstring>

namespace
{
    bool isPrimeSubgroupPoint(const osuCrypto::u8 encoded[32])
    {
        // l = 2^252 + 27742317777372353535851937790883648493.
        static const osuCrypto::u8 order[32] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
        ge25519 point, multiple;
        if (ge25519_unpack_vartime(&point, encoded) != 0)
            return false;
        ge25519_setneutral(&multiple);
        for (int bit = 255; bit >= 0; --bit)
        {
            ge25519_double(&multiple, &multiple);
            if ((order[bit >> 3] >> (bit & 7)) & 1)
                ge25519_add(&multiple, &multiple, &point);
        }
        return ge25519_isneutral_vartime(&multiple) != 0;
    }
}

namespace tests_cryptoTools
{
    void Edwards25519_4xBase_Test()
    {
        using namespace osuCrypto::Edwards25519;

        std::array<Scalar, lanes> scalars;
        std::array<std::array<osuCrypto::u8, encodedSize>, lanes> scalarBytes{};
        for (std::size_t i = 0; i != scalars.size(); ++i)
        {
            scalarBytes[i][0] = static_cast<osuCrypto::u8>(i + 1);
            scalarBytes[i][7] = static_cast<osuCrypto::u8>(17 * i);
            scalars[i].fromBytes(scalarBytes[i].data());
        }

        const auto batch = Point4::mulGenerator(scalars);
        std::array<osuCrypto::u8, lanes * encodedSize> batchPacked;
        batch.toBytes(batchPacked.data());

        for (std::size_t i = 0; i != scalars.size(); ++i)
        {
            const auto point = Point::mulGenerator(scalars[i]);
            std::array<osuCrypto::u8, encodedSize> packed;
            point.toBytes(packed.data());
            if (std::memcmp(packed.data(), batchPacked.data() + encodedSize * i,
                            packed.size()))
                throw osuCrypto::UnitTestFail(
                    "four-lane Edwards25519 base multiplication mismatch");

            const auto doubled = point + point;
            std::array<osuCrypto::u8, encodedSize> doubledPacked, sumPacked;
            doubled.toBytes(doubledPacked.data());
            point.doubled().toBytes(sumPacked.data());
            if (doubledPacked != sumPacked)
                throw osuCrypto::UnitTestFail("Edwards25519 add/double mismatch");
        }

        std::array<osuCrypto::u8, encodedSize> vectorInput{};
        for (std::size_t i = 0; i != vectorInput.size(); ++i)
            vectorInput[i] = static_cast<osuCrypto::u8>(13 * i + i * i);
        Scalar vectorScalar(vectorInput.data());
        std::array<osuCrypto::u8, encodedSize> vectorOutput;
        Point::mulGenerator(vectorScalar).toBytes(vectorOutput.data());
        const std::array<osuCrypto::u8, encodedSize> expected = {
            0x70, 0x72, 0x2e, 0x3d, 0xff, 0x9e, 0x15, 0x0e,
            0xf3, 0x73, 0x33, 0xe5, 0xda, 0x79, 0x9b, 0xf3,
            0x1e, 0x64, 0x81, 0x92, 0x2d, 0x61, 0xf4, 0x43,
            0x50, 0x27, 0x01, 0x05, 0x0c, 0x92, 0xb0, 0x56};
        if (vectorOutput != expected)
            throw osuCrypto::UnitTestFail("Edwards25519 known-answer mismatch");

        const auto broadcast = Point4::broadcast(Point::mulGenerator(vectorScalar));
        std::array<osuCrypto::u8, lanes * encodedSize> broadcastPacked;
        broadcast.toBytes(broadcastPacked.data());
        for (std::size_t i = 0; i != lanes; ++i)
            if (std::memcmp(broadcastPacked.data() + i * encodedSize,
                            expected.data(), expected.size()))
                throw osuCrypto::UnitTestFail("Edwards25519 broadcast mismatch");

        Point4 unpacked;
        if (!unpacked.fromBytes(batchPacked.data()))
            throw osuCrypto::UnitTestFail(
                "four-lane Edwards25519 point failed to unpack");

        std::array<osuCrypto::u8, lanes * encodedSize> repacked;
        unpacked.toBytes(repacked.data());
        if (repacked != batchPacked)
            throw osuCrypto::UnitTestFail(
                "four-lane Edwards25519 pack/unpack mismatch");

        std::array<sc25519, lanes> rawScalars;
        for (std::size_t i = 0; i != lanes; ++i)
            sc25519_from32bytes(&rawScalars[i], scalarBytes[i].data());
        ge4x rawBase, directProduct, tableProduct;
        ge4x_scalarsmults_base(&rawBase, rawScalars.data());
        ge4x_scalarsmults(&directProduct, &rawBase, rawScalars.data());
        alignas(32) static ge4x table[64][8];
        ge4x_maketable(table, &rawBase, 1);
        ge4x_scalarsmults_table(
            &tableProduct, table, rawScalars.data(), 1);
        std::array<osuCrypto::u8, lanes * encodedSize> directPacked, tablePacked;
        ge4x_pack(directPacked.data(), &directProduct);
        ge4x_pack(tablePacked.data(), &tableProduct);
        if (directPacked != tablePacked)
            throw osuCrypto::UnitTestFail(
                "Edwards25519 precomputed table multiplication mismatch");
    }

    void Edwards25519_HashToCurve_Test()
    {
        using namespace osuCrypto::Edwards25519;

        static const osuCrypto::u8 hashMessage[] = {'a', 'b', 'c'};
        static const osuCrypto::u8 hashDomain[] = "unit-test";
        const auto hashPoint = Point::hashToCurveElligator2(
            hashMessage, sizeof(hashMessage), hashDomain, sizeof(hashDomain) - 1);
        std::array<osuCrypto::u8, encodedSize> hashPointPacked;
        hashPoint.toBytes(hashPointPacked.data());
        const std::array<osuCrypto::u8, encodedSize> expectedHashPoint = {
            0xa6, 0x7e, 0x69, 0xe3, 0x60, 0xc2, 0x24, 0x99,
            0xaa, 0xc3, 0xb5, 0x19, 0x4a, 0x75, 0xa1, 0xf5,
            0x2b, 0xde, 0x47, 0x23, 0xc1, 0x31, 0xb7, 0x32,
            0x82, 0x6c, 0x06, 0xd3, 0x58, 0x33, 0x75, 0xc7};
        if (hashPointPacked != expectedHashPoint || hashPoint.isNeutral() ||
            !isPrimeSubgroupPoint(hashPointPacked.data()))
            throw osuCrypto::UnitTestFail(
                "Edwards25519 BLAKE2b Elligator2 known-answer mismatch");

        Point decodedHashPoint;
        if (!decodedHashPoint.fromBytes(hashPointPacked.data()))
            throw osuCrypto::UnitTestFail(
                "Edwards25519 Elligator2 output is not a valid point");

        osuCrypto::Blake2 canonicalHash(32), encodedHash(32);
        std::array<osuCrypto::u8, 32> canonicalDigest, encodedDigest;
        canonicalHash.Update(hashPoint);
        canonicalHash.Final(canonicalDigest.data());
        encodedHash.Update(hashPointPacked.data(), hashPointPacked.size());
        encodedHash.Final(encodedDigest.data());
        if (canonicalDigest != encodedDigest)
            throw osuCrypto::UnitTestFail(
                "Edwards25519 Hashable encoding is not canonical");

        static const osuCrypto::u8 otherDomain[] = "other-test";
        std::array<osuCrypto::u8, encodedSize> otherDomainPoint;
        Point::hashToCurveElligator2(
            hashMessage, sizeof(hashMessage), otherDomain,
            sizeof(otherDomain) - 1).toBytes(otherDomainPoint.data());
        if (otherDomainPoint == hashPointPacked)
            throw osuCrypto::UnitTestFail(
                "Edwards25519 Elligator2 domain separation failed");

        constexpr std::size_t batchMessageSize = 3;
        const std::array<osuCrypto::u8, lanes * batchMessageSize> batchMessages = {
            'a', 'b', 'c',
            0x00, 0x01, 0x02,
            0xff, 0x80, 0x40,
            'x', 'y', 'z'};
        const auto batchHashPoint = Point4::hashToCurveElligator2(
            batchMessages.data(), batchMessageSize,
            hashDomain, sizeof(hashDomain) - 1);
        std::array<osuCrypto::u8, lanes * encodedSize> batchHashPacked;
        batchHashPoint.toBytes(batchHashPacked.data());
        for (std::size_t lane = 0; lane != lanes; ++lane)
        {
            const auto scalarHashPoint = Point::hashToCurveElligator2(
                batchMessages.data() + lane * batchMessageSize,
                batchMessageSize, hashDomain, sizeof(hashDomain) - 1);
            std::array<osuCrypto::u8, encodedSize> scalarHashPacked;
            scalarHashPoint.toBytes(scalarHashPacked.data());
            if (std::memcmp(
                    scalarHashPacked.data(),
                    batchHashPacked.data() + lane * encodedSize,
                    encodedSize) != 0 ||
                !isPrimeSubgroupPoint(
                    batchHashPacked.data() + lane * encodedSize))
                throw osuCrypto::UnitTestFail(
                    "four-lane Edwards25519 Elligator2 mismatch");
        }

        osuCrypto::Blake2 canonicalBatchHash(32), encodedBatchHash(32);
        canonicalBatchHash.Update(batchHashPoint);
        canonicalBatchHash.Final(canonicalDigest.data());
        encodedBatchHash.Update(
            batchHashPacked.data(), batchHashPacked.size());
        encodedBatchHash.Final(encodedDigest.data());
        if (canonicalDigest != encodedDigest)
            throw osuCrypto::UnitTestFail(
                "four-lane Edwards25519 Hashable encoding is not canonical");

        std::array<osuCrypto::u8, lanes * encodedSize> emptyBatchPacked;
        Point4::hashToCurveElligator2(
            nullptr, 0, hashDomain, sizeof(hashDomain) - 1)
            .toBytes(emptyBatchPacked.data());
        std::array<osuCrypto::u8, encodedSize> emptyScalarPacked;
        Point::hashToCurveElligator2(
            nullptr, 0, hashDomain, sizeof(hashDomain) - 1)
            .toBytes(emptyScalarPacked.data());
        for (std::size_t lane = 0; lane != lanes; ++lane)
            if (std::memcmp(
                    emptyBatchPacked.data() + lane * encodedSize,
                    emptyScalarPacked.data(), encodedSize) != 0)
                throw osuCrypto::UnitTestFail(
                    "four-lane empty-message Elligator2 mismatch");

        constexpr std::size_t variedMessageSize = 17;
        std::array<osuCrypto::u8, lanes * variedMessageSize> variedMessages;
        for (std::size_t batch = 0; batch != 8; ++batch)
        {
            for (std::size_t i = 0; i != variedMessages.size(); ++i)
                variedMessages[i] = static_cast<osuCrypto::u8>(
                    29 * batch + 17 * i + i * i);
            Point4::hashToCurveElligator2(
                variedMessages.data(), variedMessageSize,
                hashDomain, sizeof(hashDomain) - 1)
                .toBytes(batchHashPacked.data());
            for (std::size_t lane = 0; lane != lanes; ++lane)
            {
                Point::hashToCurveElligator2(
                    variedMessages.data() + lane * variedMessageSize,
                    variedMessageSize, hashDomain, sizeof(hashDomain) - 1)
                    .toBytes(emptyScalarPacked.data());
                if (std::memcmp(
                        batchHashPacked.data() + lane * encodedSize,
                        emptyScalarPacked.data(), encodedSize) != 0)
                    throw osuCrypto::UnitTestFail(
                        "four-lane varied-input Elligator2 mismatch");
            }
        }
    }
}
