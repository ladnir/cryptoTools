// This file is placed in the public domain, like cryptoTools/Crypto/AES.h.
#include <cryptoTools/Crypto/AES.h>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace tests_cryptoTools { void AES_EncDec_Test(); }
using namespace osuCrypto;
using Clock = std::chrono::steady_clock;
static volatile u64 checksum;
#ifdef _MSC_VER
#define AES_BENCH_NOINLINE __declspec(noinline)
#else
#define AES_BENCH_NOINLINE __attribute__((noinline))
#endif

template<u64 batch, bool hash>
AES_BENCH_NOINLINE void fixed(const AES& aes, block* data, u64 n)
{
    for (u64 i = 0; i < n; i += batch)
        if constexpr(hash) aes.hashBlocks<batch>(data + i, data + i);
        else aes.ecbEncBlocks<batch>(data + i, data + i);
}

template<class F>
void measure(const char* name, u64 n, F fn)
{
    std::vector<block> data(n, block(123, 456));
    const u64 reps = std::max<u64>(8, (1ull << 24) / n);
    std::vector<double> times;
    for (int trial = 0; trial < 7; ++trial)
    {
        auto start = Clock::now();
        for (u64 r = 0; r < reps; ++r) fn(data.data(), n);
        auto seconds = std::chrono::duration<double>(Clock::now() - start).count();
        checksum = data[trial].get<u64>(0);
        times.push_back(seconds * 1e9 / (n * reps));
    }
    std::sort(times.begin(), times.end());
    std::cout << name << "," << n * sizeof(block) << "," << times[3]
              << "," << 16 / times[3] << "\n";
}

#ifdef OC_ENABLE_VAES
// Empirical compute ceiling: same 10 rounds / 16 blocks, but one invariant
// broadcast key, no initial whitening, and no Davies--Meyer feed-forward.
// This is NOT an encryption implementation.
AES_BENCH_NOINLINE void roundCeiling(block* data, u64 n)
{
    const auto key = _mm256_set1_epi32(123);
    for (u64 i = 0; i < n; i += 16)
    {
#define LOAD(j) auto x##j = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + 2*j))
        LOAD(0); LOAD(1); LOAD(2); LOAD(3); LOAD(4); LOAD(5); LOAD(6); LOAD(7);
#define ROUND(j) x##j = _mm256_aesenc_epi128(x##j, key)
#define ALL ROUND(0); ROUND(1); ROUND(2); ROUND(3); ROUND(4); ROUND(5); ROUND(6); ROUND(7)
        ALL; ALL; ALL; ALL; ALL; ALL; ALL; ALL; ALL; ALL;
#define STORE(j) _mm256_storeu_si256(reinterpret_cast<__m256i*>(data + i + 2*j), x##j)
        STORE(0); STORE(1); STORE(2); STORE(3); STORE(4); STORE(5); STORE(6); STORE(7);
#undef LOAD
#undef ROUND
#undef ALL
#undef STORE
    }
}
#endif

AES_BENCH_NOINLINE void memoryPass(block* data, u64 n)
{
    for (u64 i = 0; i < n; ++i) data[i] ^= block(123);
}

int main(int argc, char** argv)
{
    tests_cryptoTools::AES_EncDec_Test();
    std::cout << "AES correctness: passed\n";
    if (argc > 1 && std::string(argv[1]) == "--check") return 0;
#ifdef OC_ENABLE_VAES
    std::cout << "backend=VAES256\n";
#else
    std::cout << "backend=default\n";
#endif
    std::cout << "kernel,bytes,ns_per_block,GB_per_second\n" << std::fixed << std::setprecision(4);
    AES aes(block(1, 2));
    for (auto n : {1024ull, 524288ull, 4194304ull})
    {
#ifdef OC_ENABLE_VAES
        measure("roundCeiling16", n, roundCeiling);
#endif
        measure("memoryPass", n, memoryPass);
        measure("ecb8", n, [&](block* p, u64 s) { fixed<8, false>(aes, p, s); });
        measure("ecb16", n, [&](block* p, u64 s) { fixed<16, false>(aes, p, s); });
        measure("hash8", n, [&](block* p, u64 s) { fixed<8, true>(aes, p, s); });
        measure("hash16", n, [&](block* p, u64 s) { fixed<16, true>(aes, p, s); });
        measure("ecbBulk", n, [&](block* p, u64 s) { aes.ecbEncBlocks(p, s, p); });
        measure("hashBulk", n, [&](block* p, u64 s) { aes.hashBlocks(p, s, p); });
    }
}
