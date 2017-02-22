
#include "UnitTests.h"
#include "Tutorials/Network.h"

#include <cryptoTools/Common/Matrix.h>
using namespace osuCrypto;


int main(int argc, char** argv)
{


    Matrix<u64> m(4,5);


    MatrixView<u64> mm(m.begin(), m.end(), 2);


    m[2][1];
    //m.getView()(2, 1);
    m(2, 1);

    run_all();

    //networkTutorial();


}