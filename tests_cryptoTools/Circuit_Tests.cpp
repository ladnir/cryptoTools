#include "Circuit_Tests.h"
#include <cryptoTools/Circuit/BetaLibrary.h>

#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include <random>
#include <fstream>
#include <cryptoTools/Common/TestCollection.h>
using namespace oc;
#ifdef ENABLE_CIRCUITS


i64 signExtend(i64 v, u64 b, bool print = false)
{

    if (b != 64)
    {

        i64 loc = (i64(1) << (b - 1));
        i64 sign = v & loc;

        if (sign)
        {
            i64 mask = i64(-1) << (b);
            auto ret = v | mask;
            if (print)
            {

                std::cout << "sign: " << BitVector((u8*)&sign, 64) << std::endl;;
                std::cout << "mask: " << BitVector((u8*)&mask, 64) << std::endl;;
                std::cout << "v   : " << BitVector((u8*)&v, 64) << std::endl;;
                std::cout << "ret : " << BitVector((u8*)&ret, 64) << std::endl;;

            }
            return ret;
        }
        else
        {
            i64 mask = (i64(1) << b) - 1;
            auto ret = v & mask;
            if (print)
            {

                std::cout << "sign: " << BitVector((u8*)&loc, 64) << std::endl;;
                std::cout << "mask: " << BitVector((u8*)&mask, 64) << std::endl;;
                std::cout << "v   : " << BitVector((u8*)&v, 64) << std::endl;;
                std::cout << "ret : " << BitVector((u8*)&ret, 64) << std::endl;;

            }
            return ret;
        }
    }

    return v;
}

u64 mask(u64 v, u64 b)
{
    return v & ((1ull << b) - 1);
}

void BetaCircuit_int_Adder_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 2;


    u64 size = 57;

    for (u64 i = 0; i < tries; ++i)
    {
        size = (prng.get<u64>() % 63) + 2;// i + 2;//
        i64 a = signExtend(prng.get<i64>(), size);
        i64 b = signExtend(prng.get<i64>(), size);
        i64 c = signExtend((a + b), size);


        auto* msb = lib.int_int_add_msb(size);
        auto* cir1 = lib.int_int_add(size, size, size, BetaLibrary::Optimized::Depth);
        auto* cir2 = lib.int_int_add(size, size, size, BetaLibrary::Optimized::Size);
        auto* cir3 = lib.int_int_add(size, size, size, BetaLibrary::Optimized::Size);

        //msb->levelByAndDepth();
        cir1->levelByAndDepth();
        cir3->levelByAndDepth(BetaCircuit::LevelizeType::NoReorder);

        std::vector<BitVector> inputs(2), output1(1), output2(1), output3(1), output4(1);
        inputs[0].append((u8*)&a, size);
        inputs[1].append((u8*)&b, size);
        output1[0].resize(size);
        output2[0].resize(1);
        output3[0].resize(size);
        output4[0].resize(size);

        cir1->evaluate(inputs, output1);
        cir2->evaluate(inputs, output3);
        cir3->evaluate(inputs, output4);
        msb->evaluate(inputs, output2);
        //std::cout << "msb " << size << "  -> " << msb->mNonlinearGateCount / double(size) << std::endl;

        i64 cc = 0;
        memcpy(&cc, output1[0].data(), output1[0].sizeBytes());

        cc = signExtend(cc, size);
        if (cc != c)
        {
            std::cout << "i " << i << std::endl;

            BitVector cExp;
            cExp.append((u8*)&c, size);
            std::cout << "a  : " << inputs[0] << std::endl;
            std::cout << "b  : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output1[0] << std::endl;

            throw std::runtime_error(LOCATION);
        }


        if (output2.back().back() != output1.back().back())
        {
            std::cout << "exp: " << output1.back().back() << std::endl;
            std::cout << "act: " << output2.back().back() << std::endl;
            throw std::runtime_error(LOCATION);
        }

        if (output3.back().back() != output1.back().back())
        {
            std::cout << "exp: " << output1.back().back() << std::endl;
            std::cout << "act: " << output3.back().back() << std::endl;
            throw std::runtime_error(LOCATION);
        }
        if (output4.back().back() != output1.back().back())
        {
            std::cout << "exp: " << output1.back().back() << std::endl;
            std::cout << "act: " << output4.back().back() << std::endl;
            throw std::runtime_error(LOCATION);
        }
    }
}



void BetaCircuit_xor_and_lvl_test(const oc::CLP& cmd)
{

    u64 w = 8;
    u64 n = 10;

    BetaCircuit cir;

    BetaBundle a(w);
    BetaBundle b(w);
    BetaBundle c(w);
    BetaBundle t0(w);
    BetaBundle t1(w);
    BetaBundle z(w);

    cir.addInputBundle(a);
    cir.addInputBundle(b);
    cir.addInputBundle(c);
    cir.addTempWireBundle(t0);
    cir.addTempWireBundle(t1);
    cir.addOutputBundle(z);

    for (u64 i = 0; i < w; ++i)
    {
        cir.addGate(a[i], c[i], oc::GateType::Xor, t0[i]);
        //cir.addCopy(t0[i], t1[i]);
        cir.addGate(t0[i], b[i], oc::GateType::And, z[i]);
    }



    BitVector in0(w);
    BitVector in1(w);
    BitVector in2(w);

    for (u64 j = 0; j < n; ++j)
    {
        PRNG prng(block(0, 0));
        prng.get(in0.data(), in0.sizeBytes());
        prng.get(in1.data(), in1.sizeBytes());
        prng.get(in2.data(), in2.sizeBytes());

        std::vector<BitVector> inputs{ in0, in1, in2 };
        std::vector<BitVector> outputs{ 1 }; outputs[0].resize(w);
        cir.evaluate(inputs, outputs);


        for (u64 i = 0; i < w; ++i)
        {
            u8 exp = (in0[i] ^ in2[i]) & in1[i];
            u8 act = outputs[0][i];

            if (exp != act)
                throw RTE_LOC;
        }


        auto cirLvl = cir;
        cirLvl.levelByAndDepth();

        cirLvl.evaluate(inputs, outputs);

        for (u64 i = 0; i < w; ++i)
        {
            u8 exp = (in0[i] ^ in2[i]) & in1[i];
            u8 act = outputs[0][i];

            if (exp != act)
                throw RTE_LOC;
        }
        //std::cout << "check" << std::endl;
        //for (auto gate : cirLvl.mGates)
        //{

        //    oc::lout << "g " << gate.mInput[0] << " " << gate.mInput[1] << " " <<
        //        gateToString(gate.mType) << " " << gate.mOutput << std::endl;
        //}
    }
}


u8 msb(i64 v)
{
    return (v >> 63) & 1;
}




void BetaCircuit_SequentialOp_Test()
{

    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 10;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        auto* cirAdd = lib.int_int_add(aSize, bSize, cSize);
        //auto* cirNeg = lib.int_negate(aSize);
        auto* cirInv = lib.int_bitInvert(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((~a + b), cSize);

        std::vector<BitVector> invInputs(1), invOutput(1);
        invInputs[0].append((u8*)&a, aSize);
        invOutput[0].resize(aSize);

        cirInv->evaluate(invInputs, invOutput);


        std::vector<BitVector> addInputs(2), addOutput(1);
        addInputs[0] = invOutput[0];
        addInputs[1].append((u8*)&b, bSize);
        addOutput[0].resize(cSize);



        cirAdd->evaluate(addInputs, addOutput);

        i64 cc = 0;
        memcpy(&cc, addOutput[0].data(), addOutput[0].sizeBytes());

        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;

            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << "a  : " << invInputs[0] << std::endl;
            std::cout << "~a : " << addInputs[0] << std::endl;
            std::cout << "b  : " << addInputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << addOutput[0] << std::endl;

            throw RTE_LOC;
        }

    }

}



void BetaCircuit_int_Adder_const_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a + b), cSize);

        auto* cir = lib.int_intConst_add(aSize, bSize, b, cSize);



        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;

            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << "a  : " << inputs[0] << "  " << a << std::endl;
            std::cout << "b  : " << BitVector((u8*)&b, bSize) << "  " << b << std::endl;
            std::cout << "exp: " << cExp << "   " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;

            throw RTE_LOC;
        }

    }
}


void BetaCircuit_int_Subtractor_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {
        u64 maxSize = 64;
        u64 aSize = prng.get<u32>() % maxSize + 1,
            bSize = prng.get<u32>() % maxSize + 1,
            cSize = std::min<u64>(prng.get<u32>() % maxSize + 1, std::max(aSize, bSize) + 1);

        auto* cir = lib.int_int_subtract(aSize, bSize, cSize);
        auto* cir2 = lib.int_int_sub_msb(aSize, aSize, aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a - b), cSize);


        std::vector<BitVector> inputs(2), output(1), in2(2),out2(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);


        in2[0].append((u8*)&a, aSize);
        in2[1].append((u8*)&b, aSize);
        out2[0].resize(1);

        cir->evaluate(inputs, output);
        cir2->evaluate(in2, out2);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << std::endl;
            std::cout << "-b : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output[0] << std::endl;

            throw RTE_LOC;
        }

        if (out2[0][0] != msb(signExtend(a-b, aSize)))
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << std::endl;
            std::cout << "-b : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output[0] << std::endl;

            throw RTE_LOC;

            throw RTE_LOC;
        }
    }
}



void BetaCircuit_int_Subtractor_const_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a - b), cSize);


        auto* cir = lib.int_intConst_subtract(aSize, bSize, b, cSize);


        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << std::endl;
            std::cout << "-b : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output[0] << std::endl;

            throw RTE_LOC;
        }
    }
}


void BetaCircuit_uint_Adder_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        auto* cir = lib.uint_uint_add(aSize, bSize, cSize);


        u64 a = prng.get<i64>() & ((u64(1) << aSize) - 1);
        u64 b = prng.get<i64>() & ((u64(1) << bSize) - 1);
        u64 c = (a + b) & ((u64(1) << cSize) - 1);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        u64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;

            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << "a  : " << inputs[0] << std::endl;
            std::cout << "b  : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << std::endl;
            std::cout << "act: " << output[0] << std::endl;

            throw RTE_LOC;
        }

    }
}

void BetaCircuit_uint_Subtractor_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 1000;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 24 + 1,
            bSize = prng.get<u32>() % 24 + 1,
            cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);

        auto* cir = lib.uint_uint_subtract(aSize, bSize, cSize);

        u64 a = prng.get<i64>() & ((u64(1) << aSize) - 1);
        u64 b = prng.get<i64>() & ((u64(1) << bSize) - 1);
        u64 c = (a - b) & ((u64(1) << cSize) - 1);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        u64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << std::endl;
            std::cout << "-b : " << inputs[1] << std::endl;
            std::cout << "exp: " << cExp << "  " << c << std::endl;
            std::cout << "act: " << output[0] << "  " << cc << std::endl;

            throw RTE_LOC;
        }
    }
}


void BetaCircuit_int_Multiply_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 100;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1,
            cSize = std::min<u64>(aSize + bSize, std::min<u64>(prng.get<u32>() % 16 + 1, std::max(aSize, bSize)));

        auto* cir = lib.int_int_mult(aSize, bSize, cSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        i64 c = signExtend((a * b), cSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output, i == 125);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "*b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << cExp << "   " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;

            throw RTE_LOC;
        }
    }
}




void BetaCircuit_uint_Multiply_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 100;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1,
            cSize = std::min<u64>(aSize + bSize, std::min<u64>(prng.get<u32>() % 16 + 1, std::max(aSize, bSize)));

        auto* cir = lib.uint_uint_mult(aSize, bSize, cSize);


        u64 a = mask(prng.get<u64>(), aSize);
        u64 b = mask(prng.get<u64>(), bSize);
        u64 c = mask((a * b), cSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output, false);

        u64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = mask(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "*b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << cExp << "   " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;

            throw RTE_LOC;
        }
    }
}



void BetaCircuit_int_Divide_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1,
            cSize = aSize;

        auto* cir = lib.int_int_div(aSize, bSize, cSize);

        //std::cout << aSize << "  " << cir->mGates.size() << "  " << cir->mNonXorGateCount << std::endl;

        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        b = b ? b : signExtend(1, bSize);

        i64 c = signExtend((a / b), cSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(cSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, cSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            BitVector cExp;
            cExp.append((u8*)&c, cSize);
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "/b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << cExp << "   " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;

            throw RTE_LOC;
        }
    }
}




void BetaCircuit_int_LessThan_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_int_lt(aSize, bSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        bool c = a < b;


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(1);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if ((bool)cc != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "<b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            cir = lib.int_int_subtract(aSize, bSize, std::max(aSize, bSize));
            output.clear();
            output.emplace_back(std::max(aSize, bSize));

            cir->evaluate(inputs, output);

            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}




void BetaCircuit_int_GreaterThanEq_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_int_gteq(aSize, bSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), bSize);
        bool c = a >= b;


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(1);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (static_cast<bool>(cc) != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << ">=b: " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            cir = lib.int_int_subtract(aSize, bSize, std::max(aSize, bSize));
            output.clear();
            output.emplace_back(std::max(aSize, bSize));

            cir->evaluate(inputs, output);

            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}

void BetaCircuit_uint_LessThan_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1;

        u64 aMask = (u64(1) << aSize) - 1;
        u64 bMask = (u64(1) << bSize) - 1;


        u64 a = prng.get<u64>() & aMask;
        u64 b = prng.get<u64>() & bMask;
        bool c = a < b;


        auto* cir = lib.uint_uint_lt(aSize, bSize);
        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(1);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (static_cast<bool>(cc) != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << " a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "<b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            cir = lib.int_int_subtract(aSize, bSize, std::max(aSize, bSize));
            output.clear();
            output.emplace_back(std::max(aSize, bSize));

            cir->evaluate(inputs, output);

            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}




void BetaCircuit_uint_GreaterThanEq_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1,
            bSize = prng.get<u32>() % 16 + 1;

        u64 aMask = (u64(1) << aSize) - 1;
        u64 bMask = (u64(1) << bSize) - 1;

        u64 a = prng.get<u64>() & aMask;
        u64 b = prng.get<u64>() & bMask;
        bool c = a >= b;

        auto* cir = lib.uint_uint_gteq(aSize, bSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, bSize);
        output[0].resize(1);

        cir->evaluate(inputs, output);


        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());

        if (static_cast<bool>(cc) != c)
        {


            std::cout << "i " << i << std::endl;
            std::cout << "  a: " << inputs[0] << "  " << a << std::endl;
            std::cout << ">=b: " << inputs[1] << "  " << b << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            cir = lib.int_int_subtract(aSize, bSize, std::max(aSize, bSize));
            output.clear();
            output.emplace_back(std::max(aSize, bSize));

            cir->evaluate(inputs, output);

            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}



void BetaCircuit_multiplex_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_int_multiplex(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 b = signExtend(prng.get<i64>(), aSize);
        i64 c = prng.getBit();
        i64 d = c ? a : b;


        std::vector<BitVector> inputs(3), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&b, aSize);
        inputs[2].append((u8*)&c, 1);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != d)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "  b : " << inputs[1] << "  " << b << std::endl;
            std::cout << "  c : " << inputs[2] << "  " << c << std::endl;
            std::cout << "exp: " << d << "  " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}



void BetaCircuit_bitInvert_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_bitInvert(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 d = ~a;


        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != d)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "exp: " << d << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}



void BetaCircuit_negate_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_negate(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 d = signExtend(-a, aSize);


        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != d)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "exp: " << d << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}



void BetaCircuit_removeSign_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_removeSign(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        i64 c = signExtend(a < 0 ? -a : a, aSize);


        std::vector<BitVector> inputs(1), output(1);
        inputs[0].append((u8*)&a, aSize);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}

void BetaCircuit_addSign_Test()
{
    setThreadName("CP_Test_Thread");


    BetaLibrary lib;


    PRNG prng(ZeroBlock);
    u64 tries = 200;


    for (u64 i = 0; i < tries; ++i)
    {

        u64 aSize = prng.get<u32>() % 16 + 1;

        auto* cir = lib.int_addSign(aSize);


        i64 a = signExtend(prng.get<i64>(), aSize);
        bool sign = prng.getBit();
        i64 c = signExtend(sign ? -a : a, aSize);


        std::vector<BitVector> inputs(2), output(1);
        inputs[0].append((u8*)&a, aSize);
        inputs[1].append((u8*)&sign, 1);
        output[0].resize(aSize);

        cir->evaluate(inputs, output);

        i64 cc = 0;
        memcpy(&cc, output[0].data(), output[0].sizeBytes());
        cc = signExtend(cc, aSize);

        if (cc != c)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "  a : " << inputs[0] << "  " << a << std::endl;
            std::cout << "exp: " << c << std::endl;
            std::cout << "act: " << output[0] << "   " << cc << std::endl;


            throw RTE_LOC;
        }
    }
}


void BetaCircuit_json_Tests()
{
#ifdef USE_JSON

    std::string filename = "./test_add_cir.json";
    BetaLibrary lib;

    BetaCircuit cir = *lib.int_int_mult(64, 64, 64);
    cir.levelByAndDepth();

    std::ofstream out;
    out.open(filename, std::ios::out | std::ios::trunc | std::ios::binary);

    cir.writeJson(out);
    out.close();

    BetaCircuit cir2;
    std::ifstream in;
    in.open(filename, std::ios::in | std::ios::binary);

    if (in.is_open() == false)
        throw std::runtime_error(LOCATION);

    cir2.readJson(in);

    if (cir != cir2)
    {
        throw std::runtime_error(LOCATION);
    }
#else
    throw UnitTestSkipped("USE_JSON not defined.");
#endif
        }


void BetaCircuit_bin_Tests()
{
    std::string filename = "./test_mul_cir.bin";
    BetaLibrary lib;

    BetaCircuit cir = *lib.int_int_mult(64, 64, 64);
    cir.levelByAndDepth();

    std::ofstream out;
    out.open(filename, std::ios::out | std::ios::trunc | std::ios::binary);

    cir.writeBin(out);
    out.close();

    BetaCircuit cir2;
    std::ifstream in;
    in.open(filename, std::ios::in | std::ios::binary);

    if (in.is_open() == false)
        throw std::runtime_error(LOCATION);

    cir2.readBin(in);

    if (cir != cir2)
    {
        throw std::runtime_error(LOCATION);
    }

}

#else

auto throwNotEnabled()
{
    throw UnitTestSkipped("ENABLE_CIRCUITS not defined");
}

void BetaCircuit_SequentialOp_Test() { throwNotEnabled(); }
void BetaCircuit_xor_and_lvl_test(const oc::CLP& cmd){ throwNotEnabled(); }
void BetaCircuit_int_Adder_Test(){ throwNotEnabled(); }
void BetaCircuit_int_Adder_const_Test(){ throwNotEnabled(); }
void BetaCircuit_int_Subtractor_Test(){ throwNotEnabled(); }
void BetaCircuit_int_Subtractor_const_Test(){ throwNotEnabled(); }
void BetaCircuit_uint_Adder_Test(){ throwNotEnabled(); }
void BetaCircuit_uint_Subtractor_Test(){ throwNotEnabled(); }
void BetaCircuit_int_Multiply_Test(){ throwNotEnabled(); }
void BetaCircuit_uint_Multiply_Test(){ throwNotEnabled(); }
void BetaCircuit_int_Divide_Test(){ throwNotEnabled(); }
void BetaCircuit_int_LessThan_Test(){ throwNotEnabled(); }
void BetaCircuit_int_GreaterThanEq_Test(){ throwNotEnabled(); }
void BetaCircuit_uint_LessThan_Test(){ throwNotEnabled(); }
void BetaCircuit_uint_GreaterThanEq_Test(){ throwNotEnabled(); }
void BetaCircuit_multiplex_Test(){ throwNotEnabled(); }
void BetaCircuit_negate_Test(){ throwNotEnabled(); }
void BetaCircuit_bitInvert_Test(){ throwNotEnabled(); }
void BetaCircuit_removeSign_Test(){ throwNotEnabled(); }
void BetaCircuit_addSign_Test(){ throwNotEnabled(); }

void BetaCircuit_json_Tests(){ throwNotEnabled(); }
void BetaCircuit_bin_Tests(){ throwNotEnabled(); }

#endif
