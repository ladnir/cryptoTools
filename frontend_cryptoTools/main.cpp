
#include "../tests_cryptoTools/UnitTests.h"
#include "Tutorials/Network.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include <cryptoTools/Common/Matrix.h>
#include "cryptoTools/Common/CuckooIndex.h"
#include "cryptoTools/Common/CLP.h"
using namespace osuCrypto;
#include <sstream>
#include <fstream>

#ifdef ENABLE_CIRCUITS
#include <cryptoTools/Circuit/BetaLibrary.h>

void print_aes_bristol()
{

    //{
    //    auto name = "./AES-expanded.txt";

    //    std::ifstream file(name);

    //    BetaCircuit cir2;
    //    cir2.readBristol(file);
    //    std::cout << "and " << cir2.mNonlinearGateCount << std::endl;
    //}
    for (auto rounds : { 10, /*12, */14 })//
    {
        BetaLibrary lib;
        BetaCircuit cir;


        BetaBundle input1(256);
        BetaBundle k(128 * rounds + 128);
        BetaBundle c(128);


        cir.addInputBundle(k);
        cir.addInputBundle(input1);
        cir.addOutputBundle(c);


        // m is the fist 128 bits and cMask is the second of input1.
        BetaBundle m, cMask;
        m.mWires.insert(
            m.mWires.end(),
            input1.mWires.begin(),
            input1.mWires.begin() + 128);
        cMask.mWires.insert(
            cMask.mWires.end(),
            input1.mWires.begin() + 128,
            input1.mWires.begin() + 256);


        // c = AES_k(m)
        lib.aes_exapnded_build(cir, m, k, c);

        // c = c ^ cMask
        lib.bitwiseXor_build(cir, c, cMask, c);

        auto name = "./aes_r_" + std::to_string(rounds) + ".txt";

        {
            std::ofstream ofile(name);
            cir.writeBristol(ofile);
        }


        std::ifstream file(name);

        BetaCircuit cir2;
        cir2.readBristol(file);

        std::vector<BitVector> in(2), out1(1), out2(1);
        in[0].resize(k.size());
        in[1].resize(input1.size());
        out1[0].resize(128);
        out2[0].resize(128);

        PRNG prng(ZeroBlock);
        AES aes(prng.get<block>());

        for (u64 i = 0; i < 3; ++i)
        {

            in[1].randomize(prng);
            if (rounds == 10)
            {
                memcpy(in[0].data(), aes.mRoundKey.data(), 11 * 16);
            }
            else
            {
                in[0].randomize(prng);
            }


            cir.evaluate(in, out1);
            cir2.evaluate(in, out2);

            if (out1[0] != out2[0])
            {
                std::cout << "failed \n";
                std::cout << out1[0] << std::endl;
                std::cout << out2[0] << std::endl;
            }
            else
            {
                if (rounds == 10)
                {
                    block message = in[1].getSpan<block>()[0];
                    block mask = in[1].getSpan<block>()[1];
                    block ctxt = aes.ecbEncBlock(message) ^ mask;

                    if (neq(ctxt, out1[0].getSpan<block>()[0]))
                    {
                        std::cout << "failed bad val" << std::endl;
                    }
                    else
                    {
                        std::cout << "passed! " << cir.mNonlinearGateCount << std::endl;
                    }
                }
                else
                {
                    std::cout << "passed " << std::endl;
                }
            }

            std::cout
                << "k  " << in[0] << "\n"
                << "m  " << in[1] << "\n"
                << "c  " << out1[0] << std::endl;
        }

    }
}
#endif

int main(int argc, char** argv)
{

    CLP cmd(argc, argv);

    if (cmd.isSet("tut"))
    {
        networkTutorial();
    }
    else if(cmd.isSet("u"))
    {
        tests_cryptoTools::Tests.runIf(cmd);
    }
    else
    {
        std::cout << "Run the unit tests with:\n\n\t"
            << Color::Green << cmd.mProgramName << " -u\n\n" << Color::Default
            << "Run the  network tutorial with:\n\n\t"
            << Color::Green << cmd.mProgramName << " -tut" << Color::Default
            << std::endl;
    }
}