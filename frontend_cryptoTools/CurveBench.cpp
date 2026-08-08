#include "CurveBench.h"

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/Edwards25519/Edwards25519.h>
#include <cryptoTools/Crypto/PRNG.h>
#ifdef ENABLE_SODIUM
#include <cryptoTools/Crypto/SodiumCurve.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    using osuCrypto::PRNG;
    using osuCrypto::u64;
    namespace ed = osuCrypto::Edwards25519;

    constexpr std::size_t operationCount = 7;
    constexpr std::size_t comparedOperationCount = 5;
    constexpr std::array<const char*, operationCount> operationNames = {
        "hash_to_group", "map_to_group", "mul_generator", "scalar_mul",
        "add", "encode", "decode"};
    constexpr std::uint8_t hashDomain[] = "cryptoTools-curve-bench-v1";

    volatile std::uint8_t benchmarkSink = 0;

    struct Measurement
    {
        double nanosecondsPerPoint = 0;
        u64 iterations = 0;
    };

    template<typename Operation>
    double elapsedNanoseconds(u64 iterations, Operation& operation)
    {
        const auto begin = std::chrono::steady_clock::now();
        for (u64 i = 0; i != iterations; ++i)
            operation();
        const auto end = std::chrono::steady_clock::now();
        return std::chrono::duration<double, std::nano>(end - begin).count();
    }

    template<typename Operation>
    Measurement measure(
        Operation&& operation, u64 pointsPerIteration,
        double targetMilliseconds, u64 repetitions)
    {
        const double targetNanoseconds = targetMilliseconds * 1e6;
        u64 iterations = 1;
        double elapsed = 0;

        // Doubling calibration avoids assuming anything about the backend.
        // Each timed sample then uses the same fixed trip count.
        do
        {
            elapsed = elapsedNanoseconds(iterations, operation);
            if (elapsed >= targetNanoseconds)
                break;
            if (iterations > std::numeric_limits<u64>::max() / 2)
                throw std::overflow_error("curve benchmark iteration overflow");
            iterations *= 2;
        } while (true);

        std::vector<double> samples;
        samples.reserve(repetitions);
        for (u64 repetition = 0; repetition != repetitions; ++repetition)
            samples.emplace_back(elapsedNanoseconds(iterations, operation));
        std::sort(samples.begin(), samples.end());

        double median;
        if (samples.size() & 1)
            median = samples[samples.size() / 2];
        else
            median = (samples[samples.size() / 2 - 1] +
                      samples[samples.size() / 2]) / 2;
        return {median / (iterations * pointsPerIteration), iterations};
    }

    void consume(const ed::Point8& point)
    {
        alignas(32) std::array<std::uint8_t,
            ed::lanes * ed::encodedSize> encoded;
        point.toBytes(encoded.data());
        benchmarkSink = static_cast<std::uint8_t>(
            benchmarkSink ^ encoded[0] ^ encoded[encoded.size() - 1]);
    }

#ifndef CRYPTOTOOLS_EDWARDS25519_IFMA
    void consume(const ge4x& point)
    {
        alignas(32) std::array<std::uint8_t,
            4 * ed::encodedSize> encoded;
        ge4x_pack(encoded.data(), &point);
        benchmarkSink = static_cast<std::uint8_t>(
            benchmarkSink ^ encoded[0] ^ encoded[encoded.size() - 1]);
    }
#endif

#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
    void consume(const ge8x& point)
    {
        alignas(64) std::array<std::uint8_t,
            ed::lanes * ed::encodedSize> encoded;
        ge8x_pack(encoded.data(), &point);
        benchmarkSink = static_cast<std::uint8_t>(
            benchmarkSink ^ encoded[0] ^ encoded[encoded.size() - 1]);
    }
#endif

    std::array<ed::Scalar, ed::lanes> randomEdwardsScalars(PRNG& prng)
    {
        std::array<ed::Scalar, ed::lanes> scalars;
        std::array<std::uint8_t, ed::encodedSize> bytes;
        for (std::size_t lane = 0; lane != ed::lanes; ++lane)
        {
            prng.get(bytes.data(), bytes.size());
            scalars[lane].fromBytes(bytes.data());
        }
        return scalars;
    }

    struct EdwardsMapState
    {
        std::array<fe25519, ed::lanes> u0;
        std::array<fe25519, ed::lanes> u1;
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        alignas(64) ge8x q0;
        alignas(64) ge8x q1;
        alignas(64) ge8x result;
#else
        alignas(32) ge4x q0[2];
        alignas(32) ge4x q1[2];
        alignas(32) ge4x result[2];
#endif

        explicit EdwardsMapState(PRNG& prng)
        {
            std::array<std::uint8_t, ed::encodedSize> bytes;
            for (std::size_t lane = 0; lane != ed::lanes; ++lane)
            {
                prng.get(bytes.data(), bytes.size());
                bytes.back() &= 0x7f;
                fe25519_unpack(&u0[lane], bytes.data());
                prng.get(bytes.data(), bytes.size());
                bytes.back() &= 0x7f;
                fe25519_unpack(&u1[lane], bytes.data());
            }
        }

        void operator()()
        {
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
            ge8x_map_to_curve_elligator2(&q0, u0.data());
            ge8x_map_to_curve_elligator2(&q1, u1.data());
            ge8x_add(&result, &q0, &q1);
            ge8x_double(&result, &result);
            ge8x_double(&result, &result);
            ge8x_double(&result, &result);
#else
            ge4x_map_to_curve_elligator2(&q0[0], u0.data());
            ge4x_map_to_curve_elligator2(&q0[1], u0.data() + 4);
            ge4x_map_to_curve_elligator2(&q1[0], u1.data());
            ge4x_map_to_curve_elligator2(&q1[1], u1.data() + 4);
            ge4x_add(&result[0], &q0[0], &q1[0]);
            ge4x_add(&result[1], &q0[1], &q1[1]);
            ge4x_double(&result[0], &result[0]);
            ge4x_double(&result[1], &result[1]);
            ge4x_double(&result[0], &result[0]);
            ge4x_double(&result[1], &result[1]);
            ge4x_double(&result[0], &result[0]);
            ge4x_double(&result[1], &result[1]);
#endif
        }
    };

    std::array<Measurement, operationCount> benchmarkEdwards(
        PRNG& prng, double targetMilliseconds, u64 repetitions)
    {
        std::array<Measurement, operationCount> results;
        const auto scalars = randomEdwardsScalars(prng);
        const auto otherScalars = randomEdwardsScalars(prng);
        auto point = ed::Point8::mulGenerator(scalars);
        const auto other = ed::Point8::mulGenerator(otherScalars);
        alignas(32) std::array<std::uint8_t,
            ed::lanes * ed::encodedSize> messages;
        alignas(32) std::array<std::uint8_t,
            ed::lanes * ed::encodedSize> encoded;
        prng.get(messages.data(), messages.size());
        point.toBytes(encoded.data());

        auto hashToGroup = [&]() {
            point = ed::Point8::hashToCurveElligator2(
                messages.data(), ed::encodedSize,
                hashDomain, sizeof(hashDomain) - 1);
        };
        results[0] = measure(
            hashToGroup, ed::lanes, targetMilliseconds, repetitions);
        consume(point);

        EdwardsMapState mapState(prng);
        results[1] = measure(
            mapState, ed::lanes, targetMilliseconds, repetitions);
#ifdef CRYPTOTOOLS_EDWARDS25519_IFMA
        consume(mapState.result);
#else
        consume(mapState.result[0]);
        consume(mapState.result[1]);
#endif

        auto mulGenerator = [&]() {
            point = ed::Point8::mulGenerator(scalars);
        };
        results[2] = measure(
            mulGenerator, ed::lanes, targetMilliseconds, repetitions);
        consume(point);

        auto scalarMul = [&]() {
            point = other.mul(scalars);
        };
        results[3] = measure(
            scalarMul, ed::lanes, targetMilliseconds, repetitions);
        consume(point);

        auto add = [&]() {
            point = point + other;
        };
        results[4] = measure(
            add, ed::lanes, targetMilliseconds, repetitions);
        consume(point);

        auto encode = [&]() {
            point.toBytes(encoded.data());
        };
        results[5] = measure(
            encode, ed::lanes, targetMilliseconds, repetitions);
        benchmarkSink = static_cast<std::uint8_t>(benchmarkSink ^ encoded[0]);

        ed::Point8 decoded;
        auto decode = [&]() {
            (void)decoded.fromBytes(encoded.data());
        };
        results[6] = measure(
            decode, ed::lanes, targetMilliseconds, repetitions);
        if (!decoded.fromBytes(encoded.data()))
            throw std::runtime_error("curve benchmark produced an invalid point");
        consume(decoded);
        return results;
    }

#ifdef ENABLE_SODIUM
    struct SodiumState
    {
        using Scalar = osuCrypto::Sodium::Prime25519;
        using Point = osuCrypto::Sodium::Rist25519;

        Scalar s0, s1, s2, s3;
        Point point0, point1, point2, point3;
        Point other0, other1, other2, other3;
        std::array<std::uint8_t, 4 * Point::size> messages;
        std::array<std::uint8_t, 4 * Point::fromHashLength> uniform;
        std::array<std::uint8_t, 4 * Point::size> encoded;

        explicit SodiumState(PRNG& prng)
        {
            randomScalar(prng, s0);
            randomScalar(prng, s1);
            randomScalar(prng, s2);
            randomScalar(prng, s3);
            other0 = Point::mulGenerator(s0);
            other1 = Point::mulGenerator(s1);
            other2 = Point::mulGenerator(s2);
            other3 = Point::mulGenerator(s3);
            prng.get(messages.data(), messages.size());
            prng.get(uniform.data(), uniform.size());
            point0 = other0;
            point1 = other1;
            point2 = other2;
            point3 = other3;
        }

        static void randomScalar(PRNG& prng, Scalar& scalar)
        {
            std::array<std::uint8_t,
                crypto_core_ristretto255_NONREDUCEDSCALARBYTES> bytes;
            prng.get(bytes.data(), bytes.size());
            crypto_core_ristretto255_scalar_reduce(
                scalar.data, bytes.data());
        }

        void consumePoints()
        {
            point0.toBytes(encoded.data());
            point1.toBytes(encoded.data() + Point::size);
            point2.toBytes(encoded.data() + 2 * Point::size);
            point3.toBytes(encoded.data() + 3 * Point::size);
            benchmarkSink = static_cast<std::uint8_t>(
                benchmarkSink ^ encoded[0] ^ encoded[encoded.size() - 1]);
        }
    };

    std::array<Measurement, operationCount> benchmarkSodium(
        PRNG& prng, double targetMilliseconds, u64 repetitions)
    {
        using Point = SodiumState::Point;
        SodiumState state(prng);
        std::array<Measurement, operationCount> results;

        auto hashToGroup = [&]() {
            state.point0.fromHash(state.messages.data(), Point::size);
            state.point1.fromHash(state.messages.data() + Point::size, Point::size);
            state.point2.fromHash(state.messages.data() + 2 * Point::size, Point::size);
            state.point3.fromHash(state.messages.data() + 3 * Point::size, Point::size);
        };
        results[0] = measure(
            hashToGroup, 4, targetMilliseconds, repetitions);
        state.consumePoints();

        auto mapToGroup = [&]() {
            state.point0 = Point::fromHash(state.uniform.data());
            state.point1 = Point::fromHash(
                state.uniform.data() + Point::fromHashLength);
            state.point2 = Point::fromHash(
                state.uniform.data() + 2 * Point::fromHashLength);
            state.point3 = Point::fromHash(
                state.uniform.data() + 3 * Point::fromHashLength);
        };
        results[1] = measure(
            mapToGroup, 4, targetMilliseconds, repetitions);
        state.consumePoints();

        auto mulGenerator = [&]() {
            state.point0 = Point::mulGenerator(state.s0);
            state.point1 = Point::mulGenerator(state.s1);
            state.point2 = Point::mulGenerator(state.s2);
            state.point3 = Point::mulGenerator(state.s3);
        };
        results[2] = measure(
            mulGenerator, 4, targetMilliseconds, repetitions);
        state.consumePoints();

        auto scalarMul = [&]() {
            state.point0 = state.other0 * state.s0;
            state.point1 = state.other1 * state.s1;
            state.point2 = state.other2 * state.s2;
            state.point3 = state.other3 * state.s3;
        };
        results[3] = measure(
            scalarMul, 4, targetMilliseconds, repetitions);
        state.consumePoints();

        auto add = [&]() {
            state.point0 = state.point0 + state.other0;
            state.point1 = state.point1 + state.other1;
            state.point2 = state.point2 + state.other2;
            state.point3 = state.point3 + state.other3;
        };
        results[4] = measure(add, 4, targetMilliseconds, repetitions);
        state.consumePoints();

        auto encode = [&]() {
            state.point0.toBytes(state.encoded.data());
            state.point1.toBytes(state.encoded.data() + Point::size);
            state.point2.toBytes(state.encoded.data() + 2 * Point::size);
            state.point3.toBytes(state.encoded.data() + 3 * Point::size);
        };
        results[5] = measure(encode, 4, targetMilliseconds, repetitions);
        benchmarkSink = static_cast<std::uint8_t>(
            benchmarkSink ^ state.encoded[0]);

        auto decode = [&]() {
            state.point0.fromBytes(state.encoded.data());
            state.point1.fromBytes(state.encoded.data() + Point::size);
            state.point2.fromBytes(state.encoded.data() + 2 * Point::size);
            state.point3.fromBytes(state.encoded.data() + 3 * Point::size);
        };
        results[6] = measure(decode, 4, targetMilliseconds, repetitions);
        state.consumePoints();
        return results;
    }
#endif

    void printResults(
        const char* backend,
        const std::array<Measurement, operationCount>& results,
        std::size_t count = operationCount)
    {
        for (std::size_t i = 0; i != count; ++i)
        {
            const auto ns = results[i].nanosecondsPerPoint;
            std::cout << std::left << std::setw(22) << backend
                      << std::setw(18) << operationNames[i]
                      << std::right << std::fixed << std::setprecision(1)
                      << std::setw(14) << ns
                      << std::setprecision(3)
                      << std::setw(14) << 1e3 / ns << '\n';
        }
    }
}

void curveBench(const osuCrypto::CLP& cmd)
{
    const auto targetMilliseconds = cmd.getOr<double>("ms", 150.0);
    const auto repetitions = cmd.getOr<u64>("r", 7);
    if (targetMilliseconds <= 0 || repetitions == 0)
        throw std::invalid_argument("curve benchmark requires -ms > 0 and -r > 0");

    PRNG prng(osuCrypto::block(0x9d47a21, 0x6cb85f3));
    const auto edwards = benchmarkEdwards(
        prng, targetMilliseconds, repetitions);
    const char* edwardsBackend = ed::hasIfmaBackend ?
        "edwards25519-8x-ifma" :
        (ed::hasOptimizedBackend ? "edwards25519-8x-asm" : "edwards25519-8x-c");

    std::cout << "Curve benchmark (median of " << repetitions
              << ", >= " << targetMilliseconds << " ms/sample)\n"
              << "Times exclude input generation; hash_to_group includes the KDF, "
                 "map_to_group does not.\n"
              << "Eight-wide Edwards25519 times are normalized per point.\n\n"
              << std::left << std::setw(22) << "backend"
              << std::setw(18) << "operation"
              << std::right << std::setw(14) << "ns/point"
              << std::setw(14) << "Mpoint/s" << '\n';
    printResults(edwardsBackend, edwards);

#ifdef ENABLE_SODIUM
    const auto sodium = benchmarkSodium(
        prng, targetMilliseconds, repetitions);
    printResults("sodium-ristretto", sodium, comparedOperationCount);

    std::cout << "\nSodium / " << edwardsBackend << " time ratio:\n";
    for (std::size_t i = 0; i != comparedOperationCount; ++i)
        std::cout << "  " << std::left << std::setw(18) << operationNames[i]
                  << std::right << std::fixed << std::setprecision(2)
                  << sodium[i].nanosecondsPerPoint /
                     edwards[i].nanosecondsPerPoint << "x\n";
    std::cout << "\nSodium encoding is already compressed and its wrappers only "
                 "copy bytes; validation/decompression is charged to its group "
                 "operations above.\n";
#else
    std::cout << "\nReconfigure with ENABLE_SODIUM=ON to include the historical "
                 "Ristretto comparison.\n";
#endif

    // Keep the sink observable without polluting individual timed loops.
    if (benchmarkSink == 0xff)
        std::cerr << "";
}
