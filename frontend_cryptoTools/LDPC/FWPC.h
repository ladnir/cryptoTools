#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include <vector>

namespace osuCrypto
{
    class FWPC
    {
    public:
        u64 mNumCols;
        Matrix<u64> mRows;
        std::vector<u64> mBackingBinStarts;
        span<u64> mBinStarts;

        FWPC() = default;
        FWPC(const FWPC&) = default;
        FWPC(FWPC&&) = default;
        FWPC(u64 cols, u64 maxWidth, Matrix<u64>& rows) { insert(cols, maxWidth, rows); };
        void insert(u64 cols, u64 maxWidth, Matrix<u64>& rows);

        

        u64 cols() const { return mNumCols; }
        u64 rows() const { return mRows.rows(); }



        void blockTriangulate(
            std::vector<std::array<u64, 3>>& blocks,
            std::vector<u64>& rowPerm,
            std::vector<u64>& colPerm,
            bool verbose,
            bool stats);


        template<typename Size>
        void blockTriangulateImpl(
            std::vector<std::array<u64, 3>>& blocks,
            std::vector<u64>& rowPerm,
            std::vector<u64>& colPerm,
            bool verbose,
            bool stats);


        u64 rowWeight()
        {
            return mRows.cols();
        }

        void validate();

    };


    std::ostream& operator<<(std::ostream& o, const FWPC& s);

}
