#include "LdpcSampler.h"
#include "LdpcEncoder.h"


namespace osuCrypto
{
    void sampleExp(CLP& cmd)
    {


        u64 rows = cmd.getOr("r", 1000);
        u64 cols = rows * cmd.getOr("e", 2.0);
        u64 colWeight = cmd.getOr("cw", 4);
        u64 dWeight = cmd.getOr("dw", 3);
        u64 gap = cmd.getOr("g", 12);
        u64 tt = cmd.getOr("trials", 10);
        u64 s = cmd.getOr("s", 1);
        auto k = cols - rows;
        assert(gap >= dWeight);

        SparseMtx H;
        LdpcEncoder E;

        for (u64 i = 0; i < tt; ++i)
        {
            PRNG prng(block(i, s));
            bool b = true;
            u64 tries = 0;
            while (b)
            {
                H = sampleTriangularBand2(rows, cols, colWeight, gap, dWeight, prng);
                // H = sampleTriangular(rows, cols, colWeight, gap, prng);
                b = !E.init(H, gap);

                ++tries;

                if (tries % 1000)
                    std::cout << "\r... " << tries << std::flush;
            }


            std::cout << "\rsamples " << tries << std::endl;
            std::cout << H << std::endl;
        }
        return;

    }
}
