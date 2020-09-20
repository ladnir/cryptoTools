#include "FWPC.h"
#include "LDPC.h"
#include <assert.h>
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

        mBinStarts.resize(0);
        mBinStarts.resize(numBins);

        //for (u64 binIdx = 0; binIdx < numBins; ++binIdx)
        //{

        //    auto colBegin = (binIdx * mNumCols) / numBins;
        //    auto colEnd = ((binIdx + 1) * mNumCols) / numBins;
        //    std::cout << "bin " << binIdx << "  [" << colBegin << ", " << colEnd << ")" << std::endl;
        //}

        for (u64 i = 0; i < rows.rows(); ++i)
        {
            auto col = rows(i, 0);
            auto binIdx = (col * numBins + numBins -1) / mNumCols;

            auto colBegin = (binIdx * mNumCols) / mBinStarts.size();
            auto colEnd = ((binIdx + 1) * mNumCols) / mBinStarts.size();

            for (u64 j = 0; j < rows.cols(); ++j)
            {
                assert(rows(i, 0) >= colBegin && rows(i, 0) < colEnd);
            }

            mBinStarts[binIdx]++;

            auto row = rows[i];
            //std::cout << "add row " << i << " {";
            //for (auto s : row)
            //    std::cout << s << " ";

            //std::cout << "} to  bin " << binIdx << " at " << mBinStarts[binIdx]-1 << std::endl;

        }
        
        u64 curSize = 0;
        for (u64 i = 0; i < numBins; ++i)
        {
            auto temp = mBinStarts[i];
            mBinStarts[i] = curSize;
            curSize += temp;
        }

        mRows.resize(rows.rows(), rows.cols());
        std::vector<u64> binPos = mBinStarts;
        for (u64 i = 0; i < rows.rows(); ++i)
        {
            auto col = rows(i, 0);
            auto binIdx = (col * numBins + numBins - 1) / mNumCols;

            auto dst = mRows[binPos[binIdx]++];
            auto src = rows[i];
            std::copy(src.begin(), src.end(), dst.begin());
        }

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
        std::vector<u64>& rowPerm,
        std::vector<u64>& colPerm,
        bool verbose,
        bool stats)
    {
        auto numBins = mBinStarts.size();
        //std::vector<std::array<u64, 2>> points;
        for (auto binIdx = 0; binIdx < numBins; ++binIdx)
        {
            LDPC ldpc;
            auto rowBegin = mBinStarts[binIdx];
            auto rowEnd = (binIdx != numBins - 1) ? mBinStarts[binIdx + 1] : mRows.rows();

            assert(binIdx == (mRows(rowBegin, 0) * numBins + numBins  - 1) / mNumCols);
            auto colBegin = (binIdx * mNumCols) / numBins;
            auto colEnd = ((binIdx + 1) * mNumCols) / numBins;

            Matrix<u64> rows(rowEnd - rowBegin, mRows.cols(), AllocType::Uninitialized);


            for (u64 j = rowBegin, jj = 0; j < rowEnd; ++j, ++jj)
            {
                for (u64 k = 0; k < mRows.cols(); ++k)
                {
                    auto col = mRows(j, k);
                    assert(col >= colBegin && col < colEnd);

                    rows(jj, k) = mRows(j, k) - colBegin;
                    //points.push_back({ j - rowBegin, });
                }
            }


            ldpc.insert(colEnd - colBegin, rows);

            std::vector<std::array<u64, 3>> bb;
            std::vector<u64> rowPerm, colPerm;

            ldpc.blockTriangulate(bb, rowPerm, colPerm, verbose, false, false);

            for (auto b : bb)
            {
                blocks.push_back({ b[0] + rowBegin, b[1] + colBegin, b[2] });
            }

            //memcpy(rows.data(), &mRows(rowBegin, 0), sizeof(u64) * rows.size());

            for (u64 i = 0; i < rows.rows(); ++i)
            {
                auto row = rows[i];
                auto d = rowPerm[i];
                for (u64 j = 0; j < rows.cols(); ++j)
                {
                    auto col = row[j];
                    auto newCol = colBegin + colPerm[col];
                    mRows(rowBegin + d, j) = newCol;
                }
                //memcpy(&mRows(d, 0), &rows(i, 0), sizeof(u64) * mRows.cols());
            }
            
        }

        if (stats)
        {

            //for (u64 j = 0; j < avgs.size(); ++j)
            //{
            //    std::cout << j << " avg  " << avgs[j] / numSamples << "  max  " << max[j] << std::endl;
            //}
            std::array<u64, 3> prev = {};
            for (u64 i = 0; i < blocks.size(); ++i)
            {
                if (i == 50 && blocks.size() > 150)
                {
                    std::cout << "..." << std::endl;
                    i = blocks.size() - 50;
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