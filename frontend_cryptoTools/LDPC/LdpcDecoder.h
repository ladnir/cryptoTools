#pragma once
#include <vector>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/CLP.h"
#include "Mtx.h"
#include "simple_bitarray.h"
namespace osuCrypto
{

    class LdpcDecoder
    {
    public:
        u64 mK;

        double mP = 0.98;
        Matrix<double> mM, mR;

        std::vector<span<double>> mMM, mRR;
        std::vector<double> mMData, mRData;
        std::vector<double> mW;

        SparseMtx mH;
        //std::vector<std::vector<u64>> mCols, mRows;

        LdpcDecoder() = default;
        LdpcDecoder(const LdpcDecoder&) = default;
        LdpcDecoder(LdpcDecoder&&) = default;


        LdpcDecoder(SparseMtx& H)
        {
            init(H);
        }

        void init(SparseMtx& H);

        std::vector<u8> bpDecode(span<u8> codeword, u64 maxIter = 1000);
        std::vector<u8> logbpDecode(span<u8> codeword, u64 maxIter = 1000);


        std::vector<u8> decode(span<u8> codeword, u64 maxIter = 1000)
        {
            return bpDecode(codeword, maxIter);
        }


        //bool decode2(span<u8> data, u64 maxIter = 50);
        bool check(const span<u8>& data);

    };


    namespace tests
    {
        void LdpcDecode_pb_test(const CLP& cmd);
    }

}