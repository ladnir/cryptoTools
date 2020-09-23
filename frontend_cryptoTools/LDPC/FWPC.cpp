#include "FWPC.h"
#include "LDPC.h"
#include <assert.h>
#include "libdivide.h"
#define NDEBUG

namespace osuCrypto
{
    std::ostream& operator<<(std::ostream& o, const FWPC& s)
    {
        print(o, s.mRows, s.cols());
        return o;
    }


    void FWPC::insert(u64 c, u64 width, Matrix<u64>& rows)
    {
        mNumCols = c;
        auto numBins = (c + width - 1) / width;

        mBackingBinStarts.resize(0);
        mBackingBinStarts.resize(numBins+1);
        mBinStarts = span<u64>(mBackingBinStarts.data() + 1, mBackingBinStarts.size() - 1);

        auto numRows = rows.rows();
        auto numRows8 = (numRows / 8) * 8;

#ifndef NDEBUG
        std::vector<u64> binCutoffs(numBins + 1);
        for (u64 binIdx = 0; binIdx < binCutoffs.size(); ++binIdx)
        {
            binCutoffs[binIdx] = (binIdx * mNumCols) / numBins;
        }

        for (u64 i = 0; i < numRows; ++i)
        {
            auto col = rows(i, 0);
            auto binIdx = (col * numBins + numBins - 1) / mNumCols;

            auto colBegin = binCutoffs[binIdx];
            auto colEnd = binCutoffs[binIdx + 1];

            for (u64 j = 0; j < rows.cols(); ++j)
            {
                assert(rows(i, 0) >= colBegin && rows(i, 0) < colEnd);
            }
        }
#endif
        libdivide::divider<u64> numCols(mNumCols);

        auto  weight = rows.cols();
        auto numBinsMinusOne = numBins - 1;
        for (u64 i8 = 0; i8 < numRows8; i8 += 8)
        {
            auto basePtr = &rows(i8, 0);
            auto binIdx0 = basePtr[weight * 0];
            auto binIdx1 = basePtr[weight * 1];
            auto binIdx2 = basePtr[weight * 2];
            auto binIdx3 = basePtr[weight * 3];
            auto binIdx4 = basePtr[weight * 4];
            auto binIdx5 = basePtr[weight * 5];
            auto binIdx6 = basePtr[weight * 6];
            auto binIdx7 = basePtr[weight * 7];

            binIdx0 = binIdx0 * numBins;
            binIdx1 = binIdx1 * numBins;
            binIdx2 = binIdx2 * numBins;
            binIdx3 = binIdx3 * numBins;
            binIdx4 = binIdx4 * numBins;
            binIdx5 = binIdx5 * numBins;
            binIdx6 = binIdx6 * numBins;
            binIdx7 = binIdx7 * numBins;

            binIdx0 = binIdx0 + numBinsMinusOne;
            binIdx1 = binIdx1 + numBinsMinusOne;
            binIdx2 = binIdx2 + numBinsMinusOne;
            binIdx3 = binIdx3 + numBinsMinusOne;
            binIdx4 = binIdx4 + numBinsMinusOne;
            binIdx5 = binIdx5 + numBinsMinusOne;
            binIdx6 = binIdx6 + numBinsMinusOne;
            binIdx7 = binIdx7 + numBinsMinusOne;

            binIdx0 = binIdx0 / numCols;
            binIdx1 = binIdx1 / numCols;
            binIdx2 = binIdx2 / numCols;
            binIdx3 = binIdx3 / numCols;
            binIdx4 = binIdx4 / numCols;
            binIdx5 = binIdx5 / numCols;
            binIdx6 = binIdx6 / numCols;
            binIdx7 = binIdx7 / numCols;

            mBinStarts[binIdx0]++;
            mBinStarts[binIdx1]++;
            mBinStarts[binIdx2]++;
            mBinStarts[binIdx3]++;
            mBinStarts[binIdx4]++;
            mBinStarts[binIdx5]++;
            mBinStarts[binIdx6]++;
            mBinStarts[binIdx7]++;
        }

        for (u64 i = numRows8; i < numRows; ++i)
        {
            auto binIdx = (rows(i, 0) * numBins + numBins -1) / numCols;
            mBinStarts[binIdx]++;
        }
        
        u64 curSize = 0;
        for (u64 i = 0; i < numBins; ++i)
        {
            auto temp = mBinStarts[i];
            mBinStarts[i] = curSize;
            curSize += temp;
        }

        mRows.resize(numRows, rows.cols());
        auto row = rows.data();
        auto dstPtr = mRows.data();
        for (u64 i8 = 0; i8 < numRows8; i8 += 8)
        {
            //auto col = row[0];
            //auto binIdx = (col * numBins + numBins - 1) / numCols;
            //auto dst = mRows.data() + mBinStarts[binIdx]++ * weight;
            //memcpy(dst, row, weight * sizeof(u64));
            //row += weight;
            auto col0 = row[weight * 0];
            auto col1 = row[weight * 1];
            auto col2 = row[weight * 2];
            auto col3 = row[weight * 3];
            auto col4 = row[weight * 4];
            auto col5 = row[weight * 5];
            auto col6 = row[weight * 6];
            auto col7 = row[weight * 7];

            auto temp0 = col0 * numBins;
            auto temp1 = col1 * numBins;
            auto temp2 = col2 * numBins;
            auto temp3 = col3 * numBins;
            auto temp4 = col4 * numBins;
            auto temp5 = col5 * numBins;
            auto temp6 = col6 * numBins;
            auto temp7 = col7 * numBins;

            temp0 = temp0 + numBinsMinusOne;
            temp1 = temp1 + numBinsMinusOne;
            temp2 = temp2 + numBinsMinusOne;
            temp3 = temp3 + numBinsMinusOne;
            temp4 = temp4 + numBinsMinusOne;
            temp5 = temp5 + numBinsMinusOne;
            temp6 = temp6 + numBinsMinusOne;
            temp7 = temp7 + numBinsMinusOne;

            auto binIdx0 = temp0 / numCols;
            auto binIdx1 = temp1 / numCols;
            auto binIdx2 = temp2 / numCols;
            auto binIdx3 = temp3 / numCols;
            auto binIdx4 = temp4 / numCols;
            auto binIdx5 = temp5 / numCols;
            auto binIdx6 = temp6 / numCols;
            auto binIdx7 = temp7 / numCols;

            auto pos0 = mBinStarts[binIdx0]++;
            auto pos1 = mBinStarts[binIdx1]++;
            auto pos2 = mBinStarts[binIdx2]++;
            auto pos3 = mBinStarts[binIdx3]++;
            auto pos4 = mBinStarts[binIdx4]++;
            auto pos5 = mBinStarts[binIdx5]++;
            auto pos6 = mBinStarts[binIdx6]++;
            auto pos7 = mBinStarts[binIdx7]++;

            auto row0 = pos0 * weight;
            auto row1 = pos1 * weight;
            auto row2 = pos2 * weight;
            auto row3 = pos3 * weight;
            auto row4 = pos4 * weight;
            auto row5 = pos5 * weight;
            auto row6 = pos6 * weight;
            auto row7 = pos7 * weight;

            u64 *__restrict  dst0 = dstPtr + row0;
            u64* __restrict  dst1 = dstPtr + row1;
            u64* __restrict  dst2 = dstPtr + row2;
            u64* __restrict  dst3 = dstPtr + row3;
            u64* __restrict  dst4 = dstPtr + row4;
            u64* __restrict  dst5 = dstPtr + row5;
            u64* __restrict  dst6 = dstPtr + row6;
            u64* __restrict  dst7 = dstPtr + row7;

            u64 *__restrict src0 = row + weight * 0;
            u64 *__restrict src1 = row + weight * 1;
            u64 *__restrict src2 = row + weight * 2;
            u64 *__restrict src3 = row + weight * 3;
            u64 *__restrict src4 = row + weight * 4;
            u64 *__restrict src5 = row + weight * 5;
            u64 *__restrict src6 = row + weight * 6;
            u64 *__restrict src7 = row + weight * 7;


            memcpy(dst0, src0, weight * sizeof(u64));
            memcpy(dst1, src1, weight * sizeof(u64));
            memcpy(dst2, src2, weight * sizeof(u64));
            memcpy(dst3, src3, weight * sizeof(u64));
            memcpy(dst4, src4, weight * sizeof(u64));
            memcpy(dst5, src5, weight * sizeof(u64));
            memcpy(dst6, src6, weight * sizeof(u64));
            memcpy(dst7, src7, weight * sizeof(u64));


            row += weight * 8;
        }

        for (u64 i = numRows8; i < numRows; ++i)
        {
            auto col = row[0];
            auto binIdx = (col * numBins + numBins - 1) / numCols;
            auto dst = mRows.data() + mBinStarts[binIdx]++ * weight;
            memcpy(dst, row, weight * sizeof(u64));
            row += weight;
        }
        //mRows.resize(numRows, rows.cols());
        //auto rowPtr = rows.data();
        //for (u64 i = 0; i < numRows; ++i)
        //{
        //    auto col = *rowPtr;
        //    auto binIdx = (col * numBins + numBins - 1) / mNumCols;

        //    auto dstIdx = mBinStarts[binIdx]++;
        //    auto dst = mRows.data() + dstIdx * weight;
        //    //auto src = rows[i];
        //    memcpy(dst, rowPtr, weight);
        //    //std::copy(rowPtr, rowPtr + weight, dst);
        //    rowPtr += weight;
        //}

        mBinStarts = span<u64>(mBackingBinStarts.data(), mBackingBinStarts.size() - 1);

        //std::vector<std::vector<u64>> avgs(mNumCols);

        //for (u64 i = 0; i < rows.rows(); ++i)
        //{
        //    auto row = rows[i];
        //    u64 max = *std::max_element(row.begin(), row.end());
        //    u64 min = *std::min_element(row.begin(), row.end());

        //    if (max > min + maxWidth)
        //    {
        //        u64 newMax = 0, newMin = ~0;
        //        for (u64 j = 0; j < row.size(); ++j)
        //        {
        //            if (row[j] < min + maxWidth)
        //                newMax = std::max(newMax, row[j]);
        //            else
        //                newMin= std::min(newMin, row[j]);

        //        }

        //        max = newMax + c;
        //        min = newMin;
        //    }

        //    auto avg = (max + min) / 2;
        //    if (avg >= c)
        //        avg -= c;
        //    if (max >= c)
        //        max -= c;

        //    //avgs[avg].push_back(i);
        //    avgs[max].push_back(i);
        //}

        //mRows.resize(rows.rows(), rows.cols());
        //for (u64 i = 0, r = 0; i < avgs.size(); ++i)
        //{
        //    for (u64 j = 0; j < avgs[i].size(); ++j, ++r)
        //    {
        //        auto src = rows[avgs[i][j]];
        //        auto dst = mRows[r];
        //        std::copy(src.begin(), src.end(), dst.begin());
        //    }
        //}
    }

    void FWPC::blockTriangulate(
        std::vector<std::array<u64, 3>>& blocks,
        std::vector<u64>& rowPerm_,
        std::vector<u64>& colPerm_,
        bool verbose,
        bool stats)
    {
        u64 binWidth = (mNumCols + mBinStarts.size() - 1) / mBinStarts.size();

        if (mRows.cols() == 2)
        {
            static const int weight = 2;
            if (binWidth < std::numeric_limits<u16>::max())
                blockTriangulateImpl<u16, weight>(blocks, rowPerm_, colPerm_, verbose, stats);
            else if (binWidth < std::numeric_limits<u32>::max())
                blockTriangulateImpl<u32, weight>(blocks, rowPerm_, colPerm_, verbose, stats);
            else 
                blockTriangulateImpl<u64, weight>(blocks, rowPerm_, colPerm_, verbose, stats);
        }
        else if (mRows.cols() == 3)
        {
            static const int weight = 3;
            if (binWidth < std::numeric_limits<u16>::max())
                blockTriangulateImpl<u16, weight>(blocks, rowPerm_, colPerm_, verbose, stats);
            else if (binWidth < std::numeric_limits<u32>::max())
                blockTriangulateImpl<u32, weight>(blocks, rowPerm_, colPerm_, verbose, stats);
            else
                blockTriangulateImpl<u64, weight>(blocks, rowPerm_, colPerm_, verbose, stats);
        }
        else
        {
            throw RTE_LOC;
        }
    }


    template<typename Size, int weight>
    void FWPC::blockTriangulateImpl(
        std::vector<std::array<u64, 3>>& blocks,
        std::vector<u64>& rowPerm_,
        std::vector<u64>& colPerm_,
        bool verbose,
        bool stats)
    {
        auto numBins = mBinStarts.size();
        LDPC<Size, weight> ldpc;

        std::vector<std::array<Size, 3>> bb;
        std::vector<Size> rowPerm, colPerm;
        Matrix<Size> rows;
        auto weight = mRows.cols();

        if (stats)
        {
            std::cout << "num bins " << numBins << std::endl;
            auto pp = std::min<u64>(10, numBins);

            for (u64 binIdx = 0; binIdx < pp; ++binIdx)
            {

                auto rowBegin = mBinStarts[binIdx];
                auto rowEnd = (binIdx != numBins - 1) ? mBinStarts[binIdx + 1] : mRows.rows();
                auto numRows = rowEnd - rowBegin;
                auto numRows8 = (numRows / 8) * 8;

                assert(binIdx == (mRows(rowBegin, 0) * numBins + numBins - 1) / mNumCols);
                auto colBegin = (binIdx * mNumCols) / numBins;
                auto colEnd = ((binIdx + 1) * mNumCols) / numBins;

                auto numCols = colEnd - colBegin;
                auto load = double(numRows) / numCols;

                std::cout << "bin " << binIdx
                    << "   cols(" << colBegin << " ... " << colEnd
                    << ")  rows(" << rowBegin << " ... " << rowEnd
                    << ")  load " << load << " = " << numRows  << " / " << numCols<< std::endl;
            }

            if (pp != numBins)
            {
                std::cout << "..." << std::endl;
            }
        }

        for (u64 binIdx = 0; binIdx < numBins; ++binIdx)
        {
            auto rowBegin = mBinStarts[binIdx];
            auto rowEnd = (binIdx != numBins - 1) ? mBinStarts[binIdx + 1] : mRows.rows();
            auto numRows = rowEnd - rowBegin;
            auto numRows8 = (numRows / 8) * 8;

            assert(binIdx == (mRows(rowBegin, 0) * numBins + numBins  - 1) / mNumCols);
            auto colBegin = (binIdx * mNumCols) / numBins;
            auto colEnd = ((binIdx + 1) * mNumCols) / numBins;
            auto numCols = colEnd - colBegin;

            rows.resize(numRows, weight, AllocType::Uninitialized);

            auto src = &mRows(rowBegin, 0);
            auto dst = rows.data();
            auto size = rows.size();
            auto size8 = (size / 8) * 8;


            for (u64 i = 0; i < size8; i += 8)
            {
                dst[i + 0] = static_cast<Size>(src[i + 0] - colBegin);
                dst[i + 1] = static_cast<Size>(src[i + 1] - colBegin);
                dst[i + 2] = static_cast<Size>(src[i + 2] - colBegin);
                dst[i + 3] = static_cast<Size>(src[i + 3] - colBegin);
                dst[i + 4] = static_cast<Size>(src[i + 4] - colBegin);
                dst[i + 5] = static_cast<Size>(src[i + 5] - colBegin);
                dst[i + 6] = static_cast<Size>(src[i + 6] - colBegin);
                dst[i + 7] = static_cast<Size>(src[i + 7] - colBegin);

                assert(dst + i + 7 < rows.data() + rows.size());

                assert(dst[i + 0] < numCols);
                assert(dst[i + 1] < numCols);
                assert(dst[i + 2] < numCols);
                assert(dst[i + 3] < numCols);
                assert(dst[i + 4] < numCols);
                assert(dst[i + 5] < numCols);
                assert(dst[i + 6] < numCols);
                assert(dst[i + 7] < numCols);
            }

            for (u64 i = size8; i < size; ++i)
            {
                dst[i] = src[i] - colBegin;

                assert(dst + i < rows.data() + rows.size());
                assert(dst[i] < numCols);
            }

            ldpc.insert(colEnd - colBegin, rows);


            ldpc.blockTriangulate(bb, rowPerm, colPerm, verbose, false, false);

            for (auto b : bb)
            {
                blocks.push_back({ b[0] + rowBegin, b[1] + colBegin, b[2] });
            }


            auto rowPtr = rows.data();
            auto rowPermPtr = rowPerm.data();
            auto dstPtr = mRows.data();
            for (u64 i = 0; i < numRows8; i +=8)
            {
                //auto row = rows[i];
                auto row0 = rowPtr + 0 * weight;
                auto row1 = rowPtr + 1 * weight;
                auto row2 = rowPtr + 2 * weight;
                auto row3 = rowPtr + 3 * weight;
                auto row4 = rowPtr + 4 * weight;
                auto row5 = rowPtr + 5 * weight;
                auto row6 = rowPtr + 6 * weight;
                auto row7 = rowPtr + 7 * weight;
                rowPtr += 8 * weight;

                auto d0 = rowBegin + rowPermPtr[0];
                auto d1 = rowBegin + rowPermPtr[1];
                auto d2 = rowBegin + rowPermPtr[2];
                auto d3 = rowBegin + rowPermPtr[3];
                auto d4 = rowBegin + rowPermPtr[4];
                auto d5 = rowBegin + rowPermPtr[5];
                auto d6 = rowBegin + rowPermPtr[6];
                auto d7 = rowBegin + rowPermPtr[7];
                rowPermPtr += 8;

                d0 *= weight;
                d1 *= weight;
                d2 *= weight;
                d3 *= weight;
                d4 *= weight;
                d5 *= weight;
                d6 *= weight;
                d7 *= weight;

                auto dst0 = dstPtr + d0;
                auto dst1 = dstPtr + d1;
                auto dst2 = dstPtr + d2;
                auto dst3 = dstPtr + d3;
                auto dst4 = dstPtr + d4;
                auto dst5 = dstPtr + d5;
                auto dst6 = dstPtr + d6;
                auto dst7 = dstPtr + d7;

                for (u64 j = 0; j < weight; ++j)
                {
                    auto col0 = row0[j];
                    auto col1 = row1[j];
                    auto col2 = row2[j];
                    auto col3 = row3[j];
                    auto col4 = row4[j];
                    auto col5 = row5[j];
                    auto col6 = row6[j];
                    auto col7 = row7[j];

                    col0 = colPerm[col0];
                    col1 = colPerm[col1];
                    col2 = colPerm[col2];
                    col3 = colPerm[col3];
                    col4 = colPerm[col4];
                    col5 = colPerm[col5];
                    col6 = colPerm[col6];
                    col7 = colPerm[col7];
                                  
                    dst0[j] = colBegin + col0;
                    dst1[j] = colBegin + col1;
                    dst2[j] = colBegin + col2;
                    dst3[j] = colBegin + col3;
                    dst4[j] = colBegin + col4;
                    dst5[j] = colBegin + col5;
                    dst6[j] = colBegin + col6;
                    dst7[j] = colBegin + col7;
                }
            }

            for (u64 i = numRows8; i < numRows; ++i)
            {
                auto row = rows[i];
                auto d = rowPerm[i];
                auto dst = &mRows(rowBegin + d, 0);
                for (u64 j = 0; j < weight; ++j)
                {
                    auto col = row[j];
                    auto newCol = colBegin + colPerm[col];
                    dst[j] = newCol;
                }
            }
            
        }

        if (stats)
        {

            //for (u64 j = 0; j < avgs.size(); ++j)
            //{
            //    std::cout << j << " avg  " << avgs[j] / numSamples << "  max  " << max[j] << std::endl;
            //}
            auto ww = 10;
            std::array<u64, 3> prev = {};
            for (u64 i = 0; i < blocks.size(); ++i)
            {
                if (i == ww && blocks.size() > 2*ww)
                {
                    std::cout << "..." << std::endl;
                    i = blocks.size() - ww;
                }


                //std::string dk;
                //if (i < dks.size())
                //    dk = std::to_string(dks[i]);

                std::cout << "RC[" << i << "] " << (blocks[i][0] - prev[0]) << " " << (blocks[i][1] - prev[1]) << "  ~   " << blocks[i][2] << std::endl;
                prev = blocks[i];
            }

            if (prev[0] != mRows.rows())
            {
                std::cout << "RC[" << blocks.size() << "] " << (mRows.rows() - prev[0]) << " " << (mNumCols - prev[1]) << "  ~   0" << std::endl;
            }
        }
    }

}