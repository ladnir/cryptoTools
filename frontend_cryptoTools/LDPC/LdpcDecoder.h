#pragma once
#include <vector>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/CLP.h"
namespace osuCrypto
{

    class LdpcDecoder
    {

        u64 mK;

        double mP = 0.98;
        Matrix<double> mM, mR;
        std::vector<double> mW;

        std::vector<std::vector<u64>> mCols, mRows;

        LdpcDecoder() = default;
        LdpcDecoder(const LdpcDecoder&) = default;
        LdpcDecoder(LdpcDecoder&&) = default;


        LdpcDecoder(u64 rows, u64 cols, const std::vector<std::array<u64, 2>>& points)
        {
            init(rows, cols, points);
        }

        void init(u64 rows, u64 cols, const std::vector<std::array<u64, 2>>&);

        std::vector<u8> bpDecode(span<u8> codeword, u64 maxIter = 1000);


        std::vector<u8> decode(span<u8> codeword, u64 maxIter = 1000)
        {
            return bpDecode(codeword, maxIter);
        }

    };

    void LdpcDecode_pb_test(const CLP& cmd)
    {
        


    }

}