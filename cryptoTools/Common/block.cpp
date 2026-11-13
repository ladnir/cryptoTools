#include "block.h"

#include "Defines.h"
#include <iomanip>
#include "BitIterator.h"
#include <sstream>
#include <vector>
#include "cryptoTools/Crypto/AES.h"

namespace osuCrypto
{

    const block ZeroBlock = toBlock(0, 0);
    const block OneBlock = toBlock(0, 1);
    const block AllOneBlock = toBlock(u64(-1), u64(-1));
    const std::array<block, 2> zeroAndAllOne = { { ZeroBlock, AllOneBlock } };
    const block CCBlock = toBlock(0xcccccccccccccccc, 0xcccccccccccccccc);
    // ([]() {block cc; memset(&cc, 0xcc, sizeof(block)); return cc; })();

    template<typename T>
    void setBit(T& b, u64 idx)
    {
        *BitIterator((u8*)&b, idx) = 1;
    }

    std::array<block, 2> shiftMod(u64 s)
    {

        if (s > 127)
            throw RTE_LOC;

        static const constexpr std::array<std::uint64_t, 5> mod
        {
            0, 1, 2, 7, 128
        };
        //= 0b10000111;
        std::array<block, 2> mm{ ZeroBlock, ZeroBlock };
        for (auto b : mod)
        {
            setBit(mm, b + s);

        }
        return mm;
    }

    namespace {

        template<typename T>
        std::string bits(T x, u64 width = 99999999)
        {
            std::stringstream ss;
            BitIterator iter((u8*)&x, 0);
            for (u64 i = 0; i < sizeof(T) * 8; ++i)
            {
                if (i && (i % width == 0))
                    ss << " ";
                ss << *iter;

                ++iter;
            }
            return ss.str();
        }
    }


    block block::cc_gf128Reduce(const block& x1) const
    {
        const auto l=get<uint64_t>(), h=x1.get<uint64_t>();
        // Fold x^128 = x^7+x^2+x+1, then fold the at-most-seven overflow bits.
        const auto overflow=(h[1]>>63)^(h[1]>>62)^(h[1]>>57);
        const auto low=l[0]^h[0]^(h[0]<<1)^(h[0]<<2)^(h[0]<<7)
            ^overflow^(overflow<<1)^(overflow<<2)^(overflow<<7);
        const auto high=l[1]^h[1]^(h[1]<<1)^(h[1]<<2)^(h[1]<<7)
            ^(h[0]>>63)^(h[0]>>62)^(h[0]>>57);
        return block(high,low);
    }

}


std::ostream& operator<<(std::ostream& out, const oc::block& blk)
{
    using namespace oc;
    out << std::hex;
    u64* data = (u64*)&blk;

    out << std::setw(16) << std::setfill('0') << data[1]
        << std::setw(16) << std::setfill('0') << data[0];

    out << std::dec << std::setw(0);
    return out;
}


namespace
{
    oc::AES defaultBlockHasher(oc::block(4632453, 57432));
}

std::size_t std::hash<oc::block>::operator()(const oc::block& k) const
{
    auto h = defaultBlockHasher.ecbEncBlock(k) ^ k;
    return h.get<std::size_t>()[0];
}