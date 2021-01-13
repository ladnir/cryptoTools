

#include "cryptoTools/Common/CLP.h"
#include <vector>
#include "Mtx.h"
namespace osuCrypto
{

    std::pair<double, std::vector<u64>> minDist(const DenseMtx& mtx, bool verbose);
    DenseMtx computeGen(DenseMtx& H);
}

void rank(oc::CLP& cmd);