#pragma once

namespace osuCrypto
{
namespace details
{
namespace curve25519
{
    enum class Implementation
    {
        Avx512Ifma,
        Assembly,
        Sodium,
        Portable
    };
}
}
}
