#include "Test.h"
#include "LdpcEncoder.h"
#include "LdpcDecoder.h"
#include "LdpcSampler.h"

namespace osuCrypto
{



    void printGen(CLP& cmd)
    {

    }

    void ldpcMain(CLP& cmd)
    {
        if (cmd.isSet("print"))
            return printGen(cmd);

        if (cmd.isSet("sample"))
            return sampleExp(cmd);

        tests::Mtx_add_test();
        tests::Mtx_mult_test();
        tests::Mtx_invert_test();
        tests::Mtx_block_test();
        tests::LdpcEncoder_diagonalSolver_test();
        tests::LdpcEncoder_encode_test();
        tests::LdpcDecode_pb_test(cmd);
    }
}
