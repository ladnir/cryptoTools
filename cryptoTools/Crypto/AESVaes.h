#pragma once
// Same public-domain terms as AES.h. Included only by VAES-enabled builds.
#include <immintrin.h>
#include <cstring>

namespace osuCrypto { namespace details {
OC_FORCEINLINE __m256i aesVaesLoad(const block* p)
{
    __m256i value;
    std::memcpy(&value, p, sizeof(value));
    return value;
}
OC_FORCEINLINE void aesVaesStore(block* p, __m256i value)
{
    std::memcpy(p, &value, sizeof(value));
}
// Explicit independent YMM chains: no scratch arrays, runtime dispatch, or
// expanded-key storage. Unaligned loads preserve the
// public API's 16-byte (not 32-byte) block alignment and in-place operation.
template<bool hash, u64 blocks, class Cipher>
OC_FORCEINLINE void aesVaes256(const Cipher& aes, const block* in, block* out)
{
    static_assert(blocks >= 2 && blocks <= 16 && blocks % 2 == 0);
    __m256i x0, x1, x2, x3, x4, x5, x6, x7;
#define OC_VAES_LANES(OP) \
    OP(0); \
    if constexpr(blocks > 2) { OP(1); } \
    if constexpr(blocks > 4) { OP(2); } \
    if constexpr(blocks > 6) { OP(3); } \
    if constexpr(blocks > 8) { OP(4); } \
    if constexpr(blocks > 10) { OP(5); } \
    if constexpr(blocks > 12) { OP(6); } \
    if constexpr(blocks > 14) { OP(7); }
#define OC_VAES_INPUT(i) aesVaesLoad(in + 2*i)
#define OC_VAES_LOAD(i) x##i = _mm256_xor_si256(OC_VAES_INPUT(i), key)
    auto key = _mm256_broadcastsi128_si256(aes.mRoundKey[0].mData);
    OC_VAES_LANES(OC_VAES_LOAD);
#define OC_VAES_ROUND(i) x##i = _mm256_aesenc_epi128(x##i, key)
#define OC_VAES_STEP(r) key = _mm256_broadcastsi128_si256(aes.mRoundKey[r].mData); OC_VAES_LANES(OC_VAES_ROUND)
    OC_VAES_STEP(1); OC_VAES_STEP(2); OC_VAES_STEP(3);
    OC_VAES_STEP(4); OC_VAES_STEP(5); OC_VAES_STEP(6);
    OC_VAES_STEP(7); OC_VAES_STEP(8); OC_VAES_STEP(9);
    key = _mm256_broadcastsi128_si256(aes.mRoundKey[10].mData);
#define OC_VAES_STORE(i) \
    x##i = _mm256_aesenclast_epi128(x##i, key); \
    if constexpr(hash) x##i = _mm256_xor_si256(x##i, OC_VAES_INPUT(i)); \
    aesVaesStore(out + 2*i, x##i)
    OC_VAES_LANES(OC_VAES_STORE);
#undef OC_VAES_STORE
#undef OC_VAES_STEP
#undef OC_VAES_ROUND
#undef OC_VAES_LOAD
#undef OC_VAES_INPUT
#undef OC_VAES_LANES
}

template<bool hash, u64 blocks, class Cipher>
OC_FORCEINLINE void aesVaesBlocks(const Cipher& aes, const block* in, block* out)
{
    constexpr u64 full = blocks / 16 * 16;
    for (u64 i = 0; i < full; i += 16)
        aesVaes256<hash, 16>(aes, in + i, out + i);
    constexpr u64 tail = blocks % 16;
    if constexpr(tail >= 2)
        aesVaes256<hash, tail / 2 * 2>(aes, in + full, out + full);
    if constexpr(tail % 2)
    {
        const auto last = in[blocks - 1];
        if constexpr(hash) out[blocks - 1] = aes.ecbEncBlock(last) ^ last;
        else out[blocks - 1] = aes.ecbEncBlock(last);
    }
}
}}
