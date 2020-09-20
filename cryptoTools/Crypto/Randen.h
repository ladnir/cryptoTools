#ifndef randen_H
#define randen_H

#include <stddef.h>
#include <stdint.h>
#include <array>
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{


//#ifndef OC_ALIGN
//# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
//#  define OC_ALIGN(x) __declspec(align(x))
//# else
//#  define OC_ALIGN(x) __attribute__((aligned(x)))
//# endif
//#endif

class Randen {
public:
    static const int RANDEN_STATE_BYTES = 256;
    static const int RANDEN_SEED_BYTES = (RANDEN_STATE_BYTES - 16);


    alignas(32) std::array<u8, RANDEN_STATE_BYTES> state;
    u64 next = -1;
    using Seed = std::array<u8, RANDEN_SEED_BYTES>;


    Randen() = default;
    Randen(const Randen&) = delete;
    Randen(Randen&&);

    Randen(const Seed& seed);

    void reseed(const Seed& seed, bool clearState);
    u8   generate_byte();
    void generate_bytes(u8* out, u64 len);

};

}
#endif
