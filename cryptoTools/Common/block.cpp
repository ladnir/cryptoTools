#include "block.h"

#include "Defines.h"
#include <iomanip>
#include "BitIterator.h"
#include <sstream>
#include <vector>

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

    //std::array<block, 2> shiftOne(u64 s)
    //{
    //	if (s > 127)
    //		throw RTE_LOC;
    //	static const constexpr std::uint64_t mod = 0b10000111;
    //	block b = ZeroBlock;
    //	setBit(b, s);
    //	block m(0, mod);
    //	std::array<block, 2> ret;
    //	m.gf128Mul(b, ret[0], ret[1]);
    //	setBit(ret, s + 128);
    //	return ret;
    //}

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


    block block::_cpp_gf128Reduce(const block& x1) const
    {
        std::array<block, 2> x{ *this, x1 };
        //std::cout << "cred  " << bits(x, 128) << std::endl;

        //{
        //    BitIterator iter((u8*)x.data(), 255);
        //    std::vector<int> vv;
        //    for (int i = 0; i < 256; ++i)
        //    {
        //        vv.push_back(*iter);
        //        --iter;
        //    }
        //    std::cout << "cred* ";

        //    for (int i = 255; i >= 0; --i)
        //    {
        //        if (i == 127)
        //            std::cout << " ";
        //        std::cout << vv[i];
        //    }
        //    std::cout << std::endl;

        //}


        BitIterator iter((u8*)x.data(), 255);

        for (int i = 127; i >= 0; --i)
        {
            if (*iter)
            {
                //std::cout << " 1 " << std::endl;
                //auto xx = x;

                auto mod = shiftMod(i);
                x[0] = x[0] ^ mod[0];
                x[1] = x[1] ^ mod[1];

                //std::cout << "   " << bits(xx, 128) << std::endl;
                //std::cout << "  m" << bits(mod, 128) << std::endl;
                //std::cout << "  =" << bits(x, 128) << std::endl;
            }

            --iter;
        }
        return x[0];
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