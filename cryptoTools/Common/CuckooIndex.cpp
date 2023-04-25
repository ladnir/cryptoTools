#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include <numeric>
#include <random>
#include <algorithm>
#include <mutex>


#define CUCKOO_BATCH_SIZE 8

namespace osuCrypto
{

    // parameters for k=2 hash functions, 2^n items, and statistical security 40
    CuckooParam k2n32s40CuckooParam{ 4, 2.4, 2, u64(1) << 32 };
    CuckooParam k2n30s40CuckooParam{ 4, 2.4, 2, u64(1) << 30 };
    CuckooParam k2n28s40CuckooParam{ 2, 2.4, 2, u64(1) << 28 };
    CuckooParam k2n24s40CuckooParam{ 2, 2.4, 2, u64(1) << 24 };
    CuckooParam k2n20s40CuckooParam{ 2, 2.4, 2, u64(1) << 20 };
    CuckooParam k2n16s40CuckooParam{ 3, 2.4, 2, u64(1) << 16 };
    CuckooParam k2n12s40CuckooParam{ 5, 2.4, 2, u64(1) << 12 };
    CuckooParam k2n08s40CuckooParam{ 8, 2.4, 2, u64(1) << 8 };

    // not sure if this needs a stash of 40, but should be safe enough.
    CuckooParam k2n07s40CuckooParam{ 40, 2.4, 2, 1 << 7 };
    CuckooParam k2n06s40CuckooParam{ 40, 2.4, 2, 1 << 6 };
    CuckooParam k2n05s40CuckooParam{ 40, 2.4, 2, 1 << 5 };
    CuckooParam k2n04s40CuckooParam{ 40, 2.4, 2, 1 << 4 };
    CuckooParam k2n03s40CuckooParam{ 40, 2.4, 2, 1 << 3 };
    CuckooParam k2n02s40CuckooParam{ 40, 2.4, 2, 1 << 2 };
    CuckooParam k2n01s40CuckooParam{ 40, 2.4, 2, 1 << 1 };



    //inline void doMod32(u64* vals, const libdivide::libdivide_u64_branchfree_t* divider, const u64& modVal)
    //{
    //	//std::array<u64, 4> temp64;
    //	for (u64 i = 0; i < 32; i += 4)
    //	{
    //		__m256i row256 = _mm256_loadu_si256((__m256i*) & vals[i]);
    //		//auto temp = libdivide::libdivide_u64_do_vec256(row256, divider);
    //		auto temp = libdivide::libdivide_u64_branchfree_do_vec256(row256, divider);
    //		auto temp64 = (u64*)&temp;
    //		vals[i + 0] -= temp64[0] * modVal;
    //		vals[i + 1] -= temp64[1] * modVal;
    //		vals[i + 2] -= temp64[2] * modVal;
    //		vals[i + 3] -= temp64[3] * modVal;
    //	}
    //}

    //template<typename IdxType>
    //void mod32(u64* vals, u64 modIdx) const
    //{
    //    auto divider = &mMods[modIdx];
    //    auto modVal = mModVals[modIdx];
    //    doMod32(vals, divider, modVal);
    //}

#ifndef ENABLE_SSE


    // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_cmpgt_epi64&ig_expand=1038
    inline block _mm_cmpgt_epi64(const block& a, const block& b)
    {
        std::array<u64, 2> ret;
        ret[0] = a.get<u64>()[0] > b.get<u64>()[0] ? -1ull : 0ull;
        ret[1] = a.get<u64>()[1] > b.get<u64>()[1] ? -1ull : 0ull;

        //auto t = ::_mm_cmpgt_epi64(*(__m128i*) & a, *(__m128i*) & b);;
        //block ret2 = *(block*)&t;
        //assert(ret2 == ret);

        return ret;
    }

    // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_cmpeq_epi64&ig_expand=1038,900
    inline  block _mm_cmpeq_epi64(const block& a, const block& b)
    {
        std::array<u64, 2> ret;
        ret[0] = a.get<u64>()[0] == b.get<u64>()[0] ? -1ull : 0ull;
        ret[1] = a.get<u64>()[1] == b.get<u64>()[1] ? -1ull : 0ull;

        //auto t = ::_mm_cmpeq_epi64(*(__m128i*) & a, *(__m128i*) & b);;
        //block ret2 = *(block*)&t;
        //assert(ret2 == ret);

        return ret;
    }

    // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_sub_epi64&ig_expand=1038,900,6922
    inline block _mm_sub_epi64(const block& a, const block& b)
    {
        std::array<u64, 2> ret;
        ret[0] = a.get<u64>(0) - b.get<u64>(0);
        ret[1] = a.get<u64>(1) - b.get<u64>(1);

        //auto t = ::_mm_sub_epi64(*(__m128i*) & a, *(__m128i*) & b);;
        //block ret2 = *(block*)&t;
        //assert(ret2 == ret);

        return ret;
    }



#endif




    void buildRow(const block& hash, u32* row, span<Mod> mods)
    {
        using IdxType = u32;
        //auto h = hash;
        //std::set<u64> ss;
        //u64 i = 0;
        //while (ss.size() != mWeight)
        //{
        //	auto hh = oc::AES(h).ecbEncBlock(block(0,i++));
        //	ss.insert(hh.as<u64>()[0] % mSparseSize);
        //}
        //std::copy(ss.begin(), ss.end(), row);
        //return;
        u64 mWeight = mods.size();
        if (mWeight == 3)
        {
            u32* rr = (u32*)&hash;
            auto rr0 = *(u64*)(&rr[0]);
            auto rr1 = *(u64*)(&rr[1]);
            auto rr2 = *(u64*)(&rr[2]);
            row[0] = (IdxType)mods[0].mod(rr0);
            row[1] = (IdxType)mods[1].mod(rr1);
            row[2] = (IdxType)mods[2].mod(rr2);

            assert(row[0] < mods[0].mVal);
            assert(row[1] < mods[0].mVal);
            assert(row[2] < mods[0].mVal);

            auto min = std::min<IdxType>(row[0], row[1]);
            auto max = row[0] + row[1] - min;

            if (max == row[1])
            {
                ++row[1];
                ++max;
            }

            if (row[2] >= min)
                ++row[2];

            if (row[2] >= max)
                ++row[2];
        }
        else
        {
            auto hh = hash;
            for (u64 j = 0; j < mWeight; ++j)
            {
                auto modulus = mods[j].mVal;

                hh = hh.gf128Mul(hh);
                //std::memcpy(&h, (u8*)&hash + byteIdx, mIdxSize);
                auto colIdx = hh.get<u64>(0) % modulus;

                auto iter = row;
                auto end = row + j;
                while (iter != end)
                {
                    if (*iter <= colIdx)
                        ++colIdx;
                    else
                        break;
                    ++iter;
                }


                while (iter != end)
                {
                    end[0] = end[-1];
                    --end;
                }

                *iter = static_cast<IdxType>(colIdx);
            }
        }
    }

    void buildRow32(const block* hash, u32* row,
        span<Mod> divs)
    {
        using IdxType = u32;
        if (divs.size() == 3 /* && mSparseSize < std::numeric_limits<u32>::max()*/)
        {
            const auto weight = 3;
            block row128_[3][16];

            for (u64 i = 0; i < weight; ++i)
            {
                auto ll = (u64*)row128_[i];

                for (u64 j = 0; j < 32; ++j)
                {
                    memcpy(&ll[j], hash[j].data() + sizeof(u32) * i, sizeof(u64));
                }
                divs[i].mod32(ll);
            }


            for (u64 i = 0; i < 2; ++i)
            {
                std::array<block, 8> mask, max, min;
                //auto& row128 = *(std::array<std::array<block, 16>, 3>*)(((block*)row128_) + 8 * i);

                std::array<block*, 3> row128{
                    row128_[0] + i * 8,
                    row128_[1] + i * 8,
                    row128_[2] + i * 8 };

                //if (i)
                //{
                //	memcpy(row128[0], &row128[0][i * 8], sizeof(block) * 8);
                //	memcpy(row128[1], &row128[1][i * 8], sizeof(block) * 8);
                //	memcpy(row128[2], &row128[2][i * 8], sizeof(block) * 8);
                //}

                // mask = a > b ? -1 : 0;
                mask[0] = _mm_cmpgt_epi64(row128[0][0], row128[1][0]);
                mask[1] = _mm_cmpgt_epi64(row128[0][1], row128[1][1]);
                mask[2] = _mm_cmpgt_epi64(row128[0][2], row128[1][2]);
                mask[3] = _mm_cmpgt_epi64(row128[0][3], row128[1][3]);
                mask[4] = _mm_cmpgt_epi64(row128[0][4], row128[1][4]);
                mask[5] = _mm_cmpgt_epi64(row128[0][5], row128[1][5]);
                mask[6] = _mm_cmpgt_epi64(row128[0][6], row128[1][6]);
                mask[7] = _mm_cmpgt_epi64(row128[0][7], row128[1][7]);


                min[0] = row128[0][0] ^ row128[1][0];
                min[1] = row128[0][1] ^ row128[1][1];
                min[2] = row128[0][2] ^ row128[1][2];
                min[3] = row128[0][3] ^ row128[1][3];
                min[4] = row128[0][4] ^ row128[1][4];
                min[5] = row128[0][5] ^ row128[1][5];
                min[6] = row128[0][6] ^ row128[1][6];
                min[7] = row128[0][7] ^ row128[1][7];


                // max = max(a,b)
                max[0] = (min[0]) & mask[0];
                max[1] = (min[1]) & mask[1];
                max[2] = (min[2]) & mask[2];
                max[3] = (min[3]) & mask[3];
                max[4] = (min[4]) & mask[4];
                max[5] = (min[5]) & mask[5];
                max[6] = (min[6]) & mask[6];
                max[7] = (min[7]) & mask[7];
                max[0] = max[0] ^ row128[1][0];
                max[1] = max[1] ^ row128[1][1];
                max[2] = max[2] ^ row128[1][2];
                max[3] = max[3] ^ row128[1][3];
                max[4] = max[4] ^ row128[1][4];
                max[5] = max[5] ^ row128[1][5];
                max[6] = max[6] ^ row128[1][6];
                max[7] = max[7] ^ row128[1][7];

                // min = min(a,b)
                min[0] = min[0] ^ max[0];
                min[1] = min[1] ^ max[1];
                min[2] = min[2] ^ max[2];
                min[3] = min[3] ^ max[3];
                min[4] = min[4] ^ max[4];
                min[5] = min[5] ^ max[5];
                min[6] = min[6] ^ max[6];
                min[7] = min[7] ^ max[7];

                //if (max == b)
                //  ++b
                //  ++max
                mask[0] = _mm_cmpeq_epi64(max[0], row128[1][0]);
                mask[1] = _mm_cmpeq_epi64(max[1], row128[1][1]);
                mask[2] = _mm_cmpeq_epi64(max[2], row128[1][2]);
                mask[3] = _mm_cmpeq_epi64(max[3], row128[1][3]);
                mask[4] = _mm_cmpeq_epi64(max[4], row128[1][4]);
                mask[5] = _mm_cmpeq_epi64(max[5], row128[1][5]);
                mask[6] = _mm_cmpeq_epi64(max[6], row128[1][6]);
                mask[7] = _mm_cmpeq_epi64(max[7], row128[1][7]);
                row128[1][0] = _mm_sub_epi64(row128[1][0], mask[0]);
                row128[1][1] = _mm_sub_epi64(row128[1][1], mask[1]);
                row128[1][2] = _mm_sub_epi64(row128[1][2], mask[2]);
                row128[1][3] = _mm_sub_epi64(row128[1][3], mask[3]);
                row128[1][4] = _mm_sub_epi64(row128[1][4], mask[4]);
                row128[1][5] = _mm_sub_epi64(row128[1][5], mask[5]);
                row128[1][6] = _mm_sub_epi64(row128[1][6], mask[6]);
                row128[1][7] = _mm_sub_epi64(row128[1][7], mask[7]);
                max[0] = _mm_sub_epi64(max[0], mask[0]);
                max[1] = _mm_sub_epi64(max[1], mask[1]);
                max[2] = _mm_sub_epi64(max[2], mask[2]);
                max[3] = _mm_sub_epi64(max[3], mask[3]);
                max[4] = _mm_sub_epi64(max[4], mask[4]);
                max[5] = _mm_sub_epi64(max[5], mask[5]);
                max[6] = _mm_sub_epi64(max[6], mask[6]);
                max[7] = _mm_sub_epi64(max[7], mask[7]);

                // if (c >= min)
                //   ++c
                mask[0] = _mm_cmpgt_epi64(min[0], row128[2][0]);
                mask[1] = _mm_cmpgt_epi64(min[1], row128[2][1]);
                mask[2] = _mm_cmpgt_epi64(min[2], row128[2][2]);
                mask[3] = _mm_cmpgt_epi64(min[3], row128[2][3]);
                mask[4] = _mm_cmpgt_epi64(min[4], row128[2][4]);
                mask[5] = _mm_cmpgt_epi64(min[5], row128[2][5]);
                mask[6] = _mm_cmpgt_epi64(min[6], row128[2][6]);
                mask[7] = _mm_cmpgt_epi64(min[7], row128[2][7]);
                mask[0] = mask[0] ^ oc::AllOneBlock;
                mask[1] = mask[1] ^ oc::AllOneBlock;
                mask[2] = mask[2] ^ oc::AllOneBlock;
                mask[3] = mask[3] ^ oc::AllOneBlock;
                mask[4] = mask[4] ^ oc::AllOneBlock;
                mask[5] = mask[5] ^ oc::AllOneBlock;
                mask[6] = mask[6] ^ oc::AllOneBlock;
                mask[7] = mask[7] ^ oc::AllOneBlock;
                row128[2][0] = _mm_sub_epi64(row128[2][0], mask[0]);
                row128[2][1] = _mm_sub_epi64(row128[2][1], mask[1]);
                row128[2][2] = _mm_sub_epi64(row128[2][2], mask[2]);
                row128[2][3] = _mm_sub_epi64(row128[2][3], mask[3]);
                row128[2][4] = _mm_sub_epi64(row128[2][4], mask[4]);
                row128[2][5] = _mm_sub_epi64(row128[2][5], mask[5]);
                row128[2][6] = _mm_sub_epi64(row128[2][6], mask[6]);
                row128[2][7] = _mm_sub_epi64(row128[2][7], mask[7]);

                // if (c >= max)
                //   ++c
                mask[0] = _mm_cmpgt_epi64(max[0], row128[2][0]);
                mask[1] = _mm_cmpgt_epi64(max[1], row128[2][1]);
                mask[2] = _mm_cmpgt_epi64(max[2], row128[2][2]);
                mask[3] = _mm_cmpgt_epi64(max[3], row128[2][3]);
                mask[4] = _mm_cmpgt_epi64(max[4], row128[2][4]);
                mask[5] = _mm_cmpgt_epi64(max[5], row128[2][5]);
                mask[6] = _mm_cmpgt_epi64(max[6], row128[2][6]);
                mask[7] = _mm_cmpgt_epi64(max[7], row128[2][7]);
                mask[0] = mask[0] ^ oc::AllOneBlock;
                mask[1] = mask[1] ^ oc::AllOneBlock;
                mask[2] = mask[2] ^ oc::AllOneBlock;
                mask[3] = mask[3] ^ oc::AllOneBlock;
                mask[4] = mask[4] ^ oc::AllOneBlock;
                mask[5] = mask[5] ^ oc::AllOneBlock;
                mask[6] = mask[6] ^ oc::AllOneBlock;
                mask[7] = mask[7] ^ oc::AllOneBlock;
                row128[2][0] = _mm_sub_epi64(row128[2][0], mask[0]);
                row128[2][1] = _mm_sub_epi64(row128[2][1], mask[1]);
                row128[2][2] = _mm_sub_epi64(row128[2][2], mask[2]);
                row128[2][3] = _mm_sub_epi64(row128[2][3], mask[3]);
                row128[2][4] = _mm_sub_epi64(row128[2][4], mask[4]);
                row128[2][5] = _mm_sub_epi64(row128[2][5], mask[5]);
                row128[2][6] = _mm_sub_epi64(row128[2][6], mask[6]);
                row128[2][7] = _mm_sub_epi64(row128[2][7], mask[7]);

                //if (sizeof(IdxType) == 2)
                //{
                //	std::array<__m256i*, 3> row256{
                //		(__m256i*)row128[0],
                //		(__m256i*)row128[1],
                //		(__m256i*)row128[2]
                //	};

                //	//
                // r[0][0],r[1][1],
                // r[2][2],r[1][0],
                // r[1][1],r[1][2], 
                //
                //}
                //else 
                {
                    u64 mWeight = divs.size();
                    for (u64 j = 0; j < mWeight; ++j)
                    {
                        IdxType* __restrict rowi = row + mWeight * 16 * i;
                        u64* __restrict row64 = (u64*)(row128[j]);
                        rowi[mWeight * 0 + j] = row64[0];
                        rowi[mWeight * 1 + j] = row64[1];
                        rowi[mWeight * 2 + j] = row64[2];
                        rowi[mWeight * 3 + j] = row64[3];
                        rowi[mWeight * 4 + j] = row64[4];
                        rowi[mWeight * 5 + j] = row64[5];
                        rowi[mWeight * 6 + j] = row64[6];
                        rowi[mWeight * 7 + j] = row64[7];

                        rowi += 8 * mWeight;
                        row64 += 8;

                        rowi[mWeight * 0 + j] = row64[0];
                        rowi[mWeight * 1 + j] = row64[1];
                        rowi[mWeight * 2 + j] = row64[2];
                        rowi[mWeight * 3 + j] = row64[3];
                        rowi[mWeight * 4 + j] = row64[4];
                        rowi[mWeight * 5 + j] = row64[5];
                        rowi[mWeight * 6 + j] = row64[6];
                        rowi[mWeight * 7 + j] = row64[7];
                    }
                }
                //for (u64 k = 0; k < 16; ++k)
                //{
                //	IdxType row2[3];
                //	buildRow(hash[k + i * 16], row2);
                //	auto rowi = row + mWeight * 16 * i;
                //	//assert(rowi == row + mWeight * k);
                //	assert(row2[0] == rowi[mWeight * k + 0]);
                //	assert(row2[1] == rowi[mWeight * k + 1]);
                //	assert(row2[2] == rowi[mWeight * k + 2]);
                //}
            }
        }
        else
        {
            u64 mWeight = divs.size();
            for (u64 k = 0; k < 32; ++k)
            {
                buildRow(hash[k], row, divs);
                row += mWeight;
            }
        }
    }

    template<CuckooTypes Mode>
    CuckooIndex<Mode>::CuckooIndex()
        :mTotalTries(0)
    { }

    template<CuckooTypes Mode>
    CuckooIndex<Mode>::~CuckooIndex()
    {
    }

    template<CuckooTypes Mode>
    bool CuckooIndex<Mode>::operator==(const CuckooIndex& cmp) const
    {
        if (mBins.size() != cmp.mBins.size())
            throw std::runtime_error("");

        if (mStash.size() != cmp.mStash.size())
            throw std::runtime_error("");



        for (u64 i = 0; i < mBins.size(); ++i)
        {
            if (mBins[i].load() != cmp.mBins[i].load())
            {
                return false;
            }
        }

        for (u64 i = 0; i < mStash.size(); ++i)
        {
            if (mStash[i].load() != cmp.mStash[i].load())
            {
                return false;
            }
        }

        return true;
    }

    template<CuckooTypes Mode>
    bool CuckooIndex<Mode>::operator!=(const CuckooIndex& cmp) const
    {
        return !(*this == cmp);
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::print() const
    {

        std::cout << "Cuckoo Hasher  " << std::endl;


        for (u64 i = 0; i < mBins.size(); ++i)
        {
            std::cout << "Bin #" << i;

            if (mBins[i].isEmpty())
            {
                std::cout << " - " << std::endl;
            }
            else
            {
                std::cout << "    c_idx=" << mBins[i].idx() << "  hIdx=" << mBins[i].hashIdx() << std::endl;

            }

        }
        for (u64 i = 0; i < mStash.size() && mStash[i].isEmpty() == false; ++i)
        {
            std::cout << "Bin #" << i;

            if (mStash[i].isEmpty())
            {
                std::cout << " - " << std::endl;
            }
            else
            {
                std::cout << "    c_idx=" << mStash[i].idx() << "  hIdx=" << mStash[i].hashIdx() << std::endl;

            }

        }
        std::cout << std::endl;

    }

    template<CuckooTypes Mode>
    CuckooParam CuckooIndex<Mode>::selectParams(const u64& n, const u64& statSecParam, const u64& stashSize, const u64& hh)
    {
        double nn = std::log2(n);

        auto h = hh ? hh : 3;

        if (stashSize == 0 && h == 3)
        {
            auto nnf = log2floor(n);
            if (nnf < 9)
            {
                struct Line {
                    double slope, y;
                };
                std::array<Line, 10> lines
                { {
                    Line{5.5 , 6.35 }, //0
                    Line{5.5 , 6.35 }, //1
                    Line{5.5 , 6.35 }, //2
                    Line{ 8.5,-0.07 }, //3
                    Line{13.4,-6.74 }, //4
                    Line{21.9,-16.1 }, //5
                    Line{57.8,-62.6 }, //6
                    Line{100 ,-113 	}, //7
                    Line{142 ,-158	}, //8
                } };



                // secParam = slope * e + y
                // e = (secParam - y ) / slope;
                auto e = (statSecParam - lines[nnf].y) / lines[nnf].slope;

                return CuckooParam{ 0, e, 3, n };
            }
            else
            {

                // parameters that have been experimentally determined.
                double a = 240;
                double b = -std::log2(n) - 256;

                auto e = (statSecParam - b) / a;

                // we have the statSecParam = a e + b, where e = |cuckoo|/|set| is the expenation factor
                // therefore we have that
                //
                //   e = (statSecParam - b) / a
                //
                return CuckooParam{ 0, e, 3, n };
            }
        }
        else if (h == 2)
        {
            // parameters that have been experimentally determined.
            double
                a = -0.8,
                b = 3.3,
                c = 2.5,
                d = 14,
                f = 5,
                g = 0.65;

            // for e > 8,   statSecParam = (1 + 0.65 * stashSize) (b * std::log2(e) + a + nn).
            // for e < 8,   statSecParam -> 0 at e = 2. This is what the pow(...) does...
            auto sec = [&](double e) { return (1 + g * stashSize) * (b * std::log2(e) + a + nn - (f * nn + d) * std::pow(e, -c)); };

            // increase e util we have large enough security.
            double e = 1;
            double s = 0;
            while (s < statSecParam)
            {
                e += 1;
                s = sec(e);
            }

            return CuckooParam{ 0, e, 2, n };
        }

        throw std::runtime_error(LOCATION);

    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::init(const u64& n, const u64& statSecParam, u64 stashSize, u64 h)
    {
        init(selectParams(n, statSecParam, stashSize, h));
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::init(const CuckooParam& params)
    {
        mParams = params;

        if (CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < params.mNumHashes)
            throw std::runtime_error("parameters exceeded the maximum number of hash functions are are supported. see getHash(...); " LOCATION);

        mVals.resize(mParams.mN, AllOneBlock);
        mLocations.resize(mParams.mN, params.mNumHashes, AllocType::Uninitialized);
        u64 binCount = mParams.numBins();

        mBins.resize(binCount);
        mStash.resize(mParams.mStashSize);
        mNumBins = binCount;
        mNumBinMask = mParams.binMask();

        mMods.resize(mParams.mNumHashes);
        for (u64 i = 0; i < mMods.size(); ++i)
        {
            mMods[i] = Mod(binCount - i);
        }
    }


    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(span<block> items, block hashingSeed, u64 startIdx)
    {
        //std::array<block, 32> hashs;
        //std::array<u64, 32> idxs;
        AES hasher(hashingSeed);
        AlignedUnVector<block> h(items.size());
        hasher.hashBlocks(items, h);
        insert(h, startIdx);

        //for (u64 i = 0; i < u64(items.size()); i += u64(idxs.size()))
        //{
        //    auto min = std::min<u64>(items.size() - i, idxs.size());

        //    span<block> hashs(mVals.data() + i + startIdx, min);
        //    oc::MatrixView<u32> rows(mLocations.data(i + startIdx), min, mParams.mNumHashes);

        //    hasher.ecbEncBlocks(items.data() + i, min, hashs.data());

        //    for (u64 j = 0, jj = i; j < min; ++j, ++jj)
        //    {
        //        idxs[j] = jj + startIdx;
        //        hashs[j] = hashs[j] ^ items[jj];
        //    }

        //    computeLocations(hashs, rows);
        //    probeInsert(span<u64>(idxs.data(), min));
        //}
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::computeLocations(span<const block> hashes, oc::MatrixView<u32> rows)
    {
        u64 ii = 32;
        u64 i = 0;
        while (ii < hashes.size())
        {
            buildRow32(hashes.data() + i, rows.data(i), mMods);
            i += 32;
            ii += 32;
        }

        while (i < hashes.size())
        {
            buildRow(hashes[i], rows.data(i), mMods);
            ++i;
        }
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(span<const block> items, u64 startIdx)
    {
        std::array<u64, 32> idxs;
        if (items.size() + startIdx > mVals.size())
            throw RTE_LOC;

        if (neq(mVals[startIdx], AllOneBlock))
        {
            std::cout << IoStream::lock << "cuckoo index " << startIdx << " already inserted" << std::endl << IoStream::unlock;
            throw std::runtime_error(LOCATION);
        }


        memcpy(&mVals[startIdx], items.data(), items.size() * sizeof(block));

        for (u64 i = 0; i < u64(items.size()); i += u64(idxs.size()))
        {

            auto min = std::min<u64>(items.size() - i, idxs.size());
            for (u64 j = 0, jj = i; j < min; ++j, ++jj)
            {
                idxs[j] = jj + startIdx;
            }

            computeLocations(items.subspan(i, min),
                oc::MatrixView<u32>(mLocations.data(i + startIdx), min, mParams.mNumHashes));

            probeInsert(span<u64>(idxs.data(), min));
        }
    }


    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(const u64& inputIdx, const block& hashs)
    {
        insert(span<const block>{&hashs, 1}, inputIdx);
        //buildRow(hashs, mLocations.data(inputIdx), mMods);
        //u64 i = inputIdx;
        //probeInsert(span<u64>(&i, 1));
    }

    //    template<CuckooTypes Mode>
    //    void CuckooIndex<Mode>::insert(
    //        span<u64> inputIdxs,
    //        span<block> hashs)
    //    {
    //#ifndef NDEBUG
    //        if (inputIdxs.size() != hashs.size())
    //            throw std::runtime_error("" LOCATION);
    //#endif
    //        ...;
    //        insert(inputIdxs.size(), inputIdxs.data(), hashs.data());
    //    }

        //template<CuckooTypes Mode>
        //inline u64 CuckooIndex<Mode>::getHash(const block& hash, const u8& hashIdx, const u64& num_bins)
        //{
        //    std::array<u32, 10> h;
        //    buildRow(hash, h.data(), 3, num_bins);
        //    return h[hashIdx];
        //    //if (1)
        //    //{

        //    //    const u8* ptr = hash.data();
        //    //    ptr += 2 * hashIdx;
        //    //    //if (ptr > &hash.as<u8>()[8])
        //    //    //    throw RTE_LOC;
        //    //    static_assert(CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < 4,
        //    //        "here we assume that we dont overflow the 16 byte 'block hash'. "
        //    //        "To assume that we can have at most 4 has function, i.e. we need  2*hashIdx + sizeof(u64) < sizeof(block)");


        //    //    u64 h;
        //    //    memcpy(&h, ptr, sizeof(h));
        //    //    return h % num_bins;
        //    //}
        //    //else
        //    //{
        //    //    auto hh = mAesFixedKey.hashBlock(hash ^ block(hashIdx, hashIdx));
        //    //    return hh.get<u64>(0) % num_bins;
        //    //}

        //    //auto& bytes = hash.as<const u8>();
        //    //u64& h = *(u64*)(bytes.data() + 4 * hashIdx);

        //    //auto binMask = (1ull << log2ceil(num_bins)) - 1;
        //    //while ((binMask & h) >= num_bins)
        //    //    h = rotl<u64, 7>(h);

        //    //return getHash2(hash, hashIdx, num_bins);
        //}

        //template<CuckooTypes Mode>
        //u8 CuckooIndex<Mode>::minCollidingHashIdx(u64 target, block& hashes, u8 numHashFunctions,
        //    u64 numBins)
        //{
        //    //for (u64 i = 0; i < numHashFunctions; ++i)
        //    //{
        //    //    if (target == getHash(hashes, i, numBins))
        //    //        return u8(i);
        //    //}
        //    return -1;
        //}

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::probeInsert(
        span<u64> inputIdxsMaster)
    {
        const u64 nullIdx = (u64(-1) >> 8);
        std::array<u64, CUCKOO_BATCH_SIZE> curHashIdxs, curAddrs,
            inputIdxs, tryCounts;


        u64 i = 0;
        for (; i < CUCKOO_BATCH_SIZE; ++i)
        {
            if (i < inputIdxsMaster.size())
            {

                inputIdxs[i] = inputIdxsMaster[i];
                //
                                //mLocations[inputIdxs[i]] = expand(hashs[i], 3, mNumBins, mNumBinMask);
                                //buildRow(hashs[i], mLocations.data(inputIdxs[i]), mMods);
                                //mVals[inputIdxs[i]] = hashs[i];
                curHashIdxs[i] = 0;
                tryCounts[i] = 0;
            }
            else
            {
                inputIdxs[i] = nullIdx;
            }
        }


#if CUCKOO_BATCH_SIZE == 8
        if (inputIdxsMaster.size() > 8 && mParams.mNumHashes == 3)
        {
            while (i < inputIdxsMaster.size() - 8)
            {

                // this data fetch can be slow (after the first loop).
                // As such, lets do several fetches in parallel.

                curAddrs[0] = getHash(inputIdxs[0], curHashIdxs[0]);
                curAddrs[1] = getHash(inputIdxs[1], curHashIdxs[1]);
                curAddrs[2] = getHash(inputIdxs[2], curHashIdxs[2]);
                curAddrs[3] = getHash(inputIdxs[3], curHashIdxs[3]);
                curAddrs[4] = getHash(inputIdxs[4], curHashIdxs[4]);
                curAddrs[5] = getHash(inputIdxs[5], curHashIdxs[5]);
                curAddrs[6] = getHash(inputIdxs[6], curHashIdxs[6]);
                curAddrs[7] = getHash(inputIdxs[7], curHashIdxs[7]);


                // same thing here, this fetch is slow. Do them in parallel.
                //u64 newVal0 = inputIdxs[0] | (curHashIdxs[0] << 56);
                //oldVals[i] = 
                mBins[curAddrs[0]].swap(inputIdxs[0], curHashIdxs[0]);
                mBins[curAddrs[1]].swap(inputIdxs[1], curHashIdxs[1]);
                mBins[curAddrs[2]].swap(inputIdxs[2], curHashIdxs[2]);
                mBins[curAddrs[3]].swap(inputIdxs[3], curHashIdxs[3]);
                mBins[curAddrs[4]].swap(inputIdxs[4], curHashIdxs[4]);
                mBins[curAddrs[5]].swap(inputIdxs[5], curHashIdxs[5]);
                mBins[curAddrs[6]].swap(inputIdxs[6], curHashIdxs[6]);
                mBins[curAddrs[7]].swap(inputIdxs[7], curHashIdxs[7]);


                for (u64 j = 0; j < 8; ++j)
                {
                    if (inputIdxs[j] == nullIdx)
                    {
                        inputIdxs[j] = inputIdxsMaster[i];
                        //buildRow(hashs[i], mLocations.data(inputIdxs[j]), mMods);
                        //mVals[inputIdxs[j]] = hashs[i];
                        //mLocations[inputIdxs[j]] = expand(hashs[i], 3,mNumBins, mNumBinMask);
                        curHashIdxs[j] = 0;
                        tryCounts[j] = 0;
                        ++i;
                    }
                    else
                    {
                        if (tryCounts[j] != mReinsertLimit)
                        {
                            curHashIdxs[j] = (1 + curHashIdxs[j]) % 3;
                            ++tryCounts[j];
                        }
                        else
                        {

                            u64 k = ~u64(0);
                            do
                            {
                                ++k;
                                if (k == mStash.size())
                                {
                                    std::cout << "cuckoo stash overflow" << std::endl;
                                    throw RTE_LOC;
                                }
                            } while (mStash[k].isEmpty() == false);
                            mStash[k].swap(inputIdxs[j], curHashIdxs[j]);

                            inputIdxs[j] = inputIdxsMaster[i];
                            //mLocations[inputIdxs[j]] = expand(hashs[i], 3, mNumBins, mNumBinMask);
                            //buildRow(hashs[i], mLocations.data(inputIdxs[j]), mMods);
                            //mVals[inputIdxs[j]] = hashs[i];
                            curHashIdxs[j] = 0;
                            tryCounts[j] = 0;
                            ++i;
                        }
                    }
                }
            }
        }
#endif
        for (u64 j = 0; j < CUCKOO_BATCH_SIZE; ++j)
        {

            if (inputIdxs[j] != nullIdx)
            {
                insertOne(inputIdxs[j], curHashIdxs[j], tryCounts[j]);
            }
        }


        while (i < inputIdxsMaster.size())
        {
            //mLocations[inputIdxsMaster[i]] = expand(hashs[i], mMods, mNumBinMask);
            //buildRow(hashs[i], mLocations.data(inputIdxsMaster[i]), mMods);
            //mVals[inputIdxsMaster[i]] = hashs[i];
            insertOne(inputIdxsMaster[i], 0, 0);
            ++i;
        }
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insertOne(
        u64 inputIdx, u64 curHashIdx, u64 tryIdx)
    {
        const u64 nullIdx = (u64(-1) >> 8);
        while (true)
        {
            auto curAddr = getHash(inputIdx, curHashIdx);
            mBins[curAddr].swap(inputIdx, curHashIdx);

            if (inputIdx == nullIdx)
            {
                return;
            }
            else
            {
                if (tryIdx != mReinsertLimit)
                {
                    curHashIdx = (1 + curHashIdx) % mParams.mNumHashes;
                    ++tryIdx;
                }
                else
                {
                    u64 k = ~u64(0);
                    do
                    {
                        ++k;
                        if (k == mStash.size())
                        {
                            std::cout << "cuckoo stash overflow" << std::endl;
                            std::cout << inputIdx << " { ";

                            for (u64 j = 0; j < mParams.mNumHashes; ++j)
                            {
                                if (j)
                                    std::cout << ", ";
                                std::cout << getHash(inputIdx, j);
                            }
                            std::cout << "}\n";
                            std::cout << *this << std::endl;
                            throw RTE_LOC;
                        }
                    } while (mStash[k].isEmpty() == false);
                    mStash[k].swap(inputIdx, curHashIdx);
                    return;
                }
            }
        }
    }



    template<CuckooTypes Mode>
    u64 CuckooIndex<Mode>::getHash(const u64& inputIdx, const u64& hashIdx)
    {
        assert(mVals[inputIdx] != AllOneBlock);
        assert(mLocations(inputIdx, hashIdx) < mBins.size());
        return mLocations(inputIdx, hashIdx);
        //return CuckooIndex<Mode>::getHash3(mLocations[inputIdx], hashIdx, mNumBinMask);
        //return CuckooIndex<Mode>::getHash(mLocations[inputIdx], hashIdx, mNumBins);
    }




    template<CuckooTypes Mode>
    typename CuckooIndex<Mode>::FindResult CuckooIndex<Mode>::find(
        const block& hashes_)
    {
        //auto hashes = expand(hashes_, mMods, mNumBinMask);
        auto hashes = hashes_;
        if (mParams.mNumHashes == 2)
        {
            std::array<u32, 2>  addr;;
            computeLocations(span<const block>(&hashes_, 1), MatrixView<u32>(addr.data(), 1, 2));

            std::array<u64, 2> val{
                mBins[addr[0]].load(),
                mBins[addr[1]].load() };

            if (val[0] != u64(-1))
            {
                u64 itemIdx = val[0] & (u64(-1) >> 8);

                bool match = eq(mVals[itemIdx], hashes);

                if (match) return { itemIdx, addr[0] };
            }

            if (val[1] != u64(-1))
            {
                u64 itemIdx = val[1] & (u64(-1) >> 8);

                bool match = eq(mVals[itemIdx], hashes);

                if (match) return { itemIdx, addr[1] };
            }


            // stash
            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
                u64 val = mStash[i].load();
                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mVals[itemIdx], hashes);

                    if (match)
                    {
                        return { itemIdx, i + mBins.size() };
                    }
                }

                ++i;
            }

        }
        else
        {
            std::array<u32, CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT>  addr;;
            computeLocations(span<const block>(&hashes, 1), MatrixView<u32>(addr.data(), 1, mParams.mNumHashes));

            for (u64 i = 0; i < mParams.mNumHashes; ++i)
            {
                //u64 xrHashVal = getHash(hashes, i, mNumBins);
                //auto addr = (xrHashVal) % mBins.size();


                u64 val = mBins[addr[i]].load();

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mVals[itemIdx], hashes);

                    if (match)
                    {
                        return { itemIdx, addr[i] };
                    }
                }
            }

            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
                u64 val = mStash[i].load();

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mVals[itemIdx], hashes);

                    if (match)
                    {
                        return { itemIdx, i + mBins.size() };
                    }
                }

                ++i;
            }
        }

        return { ~0ull,~0ull };
    }


    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::find(
        span<block> hashes,
        span<u64> idxs)
    {
#ifndef NDEBUG
        if (hashes.size() != idxs.size())
            throw std::runtime_error(LOCATION);
#endif

        for (u64 i = 0; i < hashes.size(); ++i)
            idxs[i] = find(hashes[i]);
    }




    //template<CuckooTypes Mode>
    //void CuckooIndex<Mode>::find(const u64& numItemsMaster, const block* hashesMaster, const u64* idxsMaster)
    //{
    //    std::array<std::array<u64, 2>, CUCKOO_BATCH_SIZE> findVal;
    //    std::array<u64, CUCKOO_BATCH_SIZE> idxs;
    //    //std::array<block, BATCH_SIZE> idxs;


    //    for (u64 step = 0; step < (numItemsMaster + findVal.size() - 1) / findVal.size(); ++step)
    //    {
    //        auto numItems = std::min<u64>(numItemsMaster - findVal.size() * step, findVal.size());

    //        //auto idxs = idxsMaster + step * findVal.size();
    //        memcpy(idxs.data(), idxsMaster + step * findVal.size(), sizeof(u64) * CUCKOO_BATCH_SIZE);
    //        auto hashes = hashesMaster + step * findVal.size();

    //        if (mParams.mNumHashes == 2)
    //        {
    //            std::array<u64, 2>  addr;

    //            for (u64 i = 0; i < numItems; ++i)
    //            {
    //                idxs[i] = -1;

    //                addr[0] = getHash(hashes[i], 0, mNumBins);
    //                addr[1] = getHash(hashes[i], 1, mNumBins);

    //                findVal[i][0] = mBins[addr[0]].load();
    //                findVal[i][1] = mBins[addr[1]].load();
    //            }

    //            for (u64 i = 0; i < numItems; ++i)
    //            {
    //                if (findVal[i][0] != u64(-1))
    //                {
    //                    u64 itemIdx = findVal[i][0] & (u64(-1) >> 8);
    //                    bool match = eq(mVals[itemIdx], hashes[i]);
    //                    if (match)
    //                    {
    //                        idxs[i] = itemIdx;
    //                    }
    //                }

    //                if (findVal[i][1] != u64(-1))
    //                {
    //                    u64 itemIdx = findVal[i][1] & (u64(-1) >> 8);
    //                    bool match = eq(mVals[itemIdx], hashes[i]);
    //                    if (match) idxs[i] = itemIdx;
    //                }
    //            }

    //            // stash

    //            u64 i = 0;
    //            while (i < mStash.size() && mStash[i].isEmpty() == false)
    //            {
    //                u64 val = mStash[i].load();
    //                if (val != u64(-1))
    //                {
    //                    u64 itemIdx = val & (u64(-1) >> 8);

    //                    for (u64 j = 0; j < numItems; ++j)
    //                    {
    //                        bool match = eq(mVals[itemIdx], hashes[i]);
    //                        if (match) idxs[j] = itemIdx;
    //                    }
    //                }

    //                ++i;
    //            }
    //        }
    //        else
    //        {
    //            throw std::runtime_error("not implemented");
    //        }
    //    }

    //}


    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::validate(span<block> inputs, block hashingSeed)
    {
        AES hasher(hashingSeed);
        u64 insertCount = 0;

        for (u64 i = 0; i < u64(inputs.size()); ++i)
        {

            block hash = hasher.hashBlock(inputs[i]);

            //hash = expand(hash, mMods, mNumBinMask);

            if (neq(hash, mVals[i]))
                throw std::runtime_error(LOCATION);

            if (neq(mVals[i], AllOneBlock))
            {
                ++insertCount;
                u64 matches(0);
                std::vector<u64> hashes(mParams.mNumHashes);
                for (u64 j = 0; j < mParams.mNumHashes; ++j)
                {
                    auto h = hashes[j] = getHash(i, j);
                    auto duplicate = (std::find(hashes.begin(), hashes.begin() + j, h) != (hashes.begin() + j));

                    if (duplicate == false && mBins[h].isEmpty() == false && mBins[h].idx() == i)
                    {
                        ++matches;
                    }
                }

                if (matches != 1)
                    throw std::runtime_error(LOCATION);
            }
        }

        u64 nonEmptyCount(0);
        for (u64 i = 0; i < mBins.size(); ++i)
        {
            if (mBins[i].isEmpty() == false)
                ++nonEmptyCount;
        }

        if (nonEmptyCount != insertCount)
            throw std::runtime_error(LOCATION);
    }

    template<CuckooTypes Mode>
    u64 CuckooIndex<Mode>::stashUtilization() const
    {
        u64 i = 0;
        while (i < mStash.size() && mStash[i].isEmpty() == false)
        {
            ++i;
        }

        return i;
    }


    //    bool CuckooIndex<Mode>::Bin::isEmpty() const
    //    {
    //        return mVal == u64(-1);
    //    }
    //
    //    u64 CuckooIndex<Mode>::Bin::idx() const
    //    {
    //        return mVal  & (u64(-1) >> 8);
    //    }
    //
    //    u64 CuckooIndex<Mode>::Bin::hashIdx() const
    //    {
    //        return mVal >> 56;
    //    }
    //
    //    void CuckooIndex<Mode>::Bin::swap(u64 & idx, u64 & hashIdx)
    //    {
    //        u64 newVal = idx | (hashIdx << 56);
    //#ifdef THREAD_SAFE_CUCKOO
    //        u64 oldVal = mVal.exchange(newVal, std::memory_order_relaxed);
    //#else
    //        u64 oldVal = mVal;
    //        mVal = newVal;
    //#endif
    //        if (oldVal == u64(-1))
    //        {
    //            idx = hashIdx = u64(-1);
    //        }
    //        else
    //        {
    //            idx = oldVal & (u64(-1) >> 8);
    //            hashIdx = oldVal >> 56;
    //        }
    //    }


    template class CuckooIndex<ThreadSafe>;
    template class CuckooIndex<NotThreadSafe>;
    }
