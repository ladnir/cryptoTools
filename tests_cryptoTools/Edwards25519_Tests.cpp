#include "tests_cryptoTools/Edwards25519_Tests.h"

#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Crypto/Edwards25519/Edwards25519.h>

#include <array>
#include <cstring>

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
}
