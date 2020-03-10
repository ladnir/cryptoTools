//#include "stdafx.h"

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/TestCollection.h>
using namespace osuCrypto;


namespace tests_cryptoTools
{
#ifdef ENABLE_RELIC

    void REccpNumber_Test()
    {
        {

            //int order = 0x18;

            REllipticCurve curve;
            PRNG prng(ZeroBlock);

            auto mod = curve.getOrder();
            REccNumber one(1);
            REccNumber zero(0);

            //auto g = curve.getGenerator();
            //auto zeroPoint = g * curve.getOrder();

            //if (zeroPoint + g != g)
            //	throw std::runtime_error(LOCATION);

            if (one + one != 2)
            {
                std::cout << one + one << std::endl;
                throw UnitTestFail("1 + 1 != 2");
            }

            if (one != one * one)
            {
                std::cout << one << std::endl;
                std::cout << one * one << std::endl;
                throw UnitTestFail("1 != 1* 1");
            }


            u64 tryCount = 10;
            //bool ok = false;
            for (u64 i = 0; i < tryCount; ++i)
            {
                REccNumber rand1(prng);
                REccNumber rand2(prng);
                //std::cout << var << std::endl;

                //if (var == 22)
                //{
                //    ok = true;
                //}

                if (rand1 > (mod - 1))
                {
                    std::cout << "bad rand'" << std::endl;
                    std::cout << "var " << rand1 << std::endl;
                    std::cout << "mod " << std::hex << mod << std::dec << std::endl;
                    std::cout << "odr " << curve.getOrder() << std::endl;
                    throw UnitTestFail("bad rand'");
                }

                if (rand1 == rand2)
                {
                    std::cout << "bad rand (eq) " << rand1 << " " << rand2 << std::endl;
                    throw UnitTestFail("rand are eq");
                }
            }

            //if (ok == false)
            //{
            //    std::cout << "bad rand 22" << std::endl;
            //    throw UnitTestFail("bad rand 22");
            //}


            REccNumber rand(prng), r;

            std::vector<u8> buff(rand.sizeBytes());

            rand.toBytes(buff.data());

            r.fromBytes(buff.data());

            if (r != rand)
            {
                std::cout << " r    " << r << std::endl;
                std::cout << " rand " << rand << std::endl;
                throw UnitTestFail(LOCATION);
            }

            if (rand - rand != 0)
            {
                throw std::runtime_error("x - x != 0 " LOCATION);
            }

            if (rand + rand.negate() != 0)
            {
                std::cout << "order       = " << curve.getOrder() << std::endl;
                std::cout << "x           = " << rand << std::endl;
                std::cout << "x.neg()     = " << rand.negate() << std::endl;
                std::cout << "x + x.neg() = " << rand + rand.negate() << std::endl;

                throw std::runtime_error("x + x.negate() != 0 " LOCATION);
            }
        }



        {
            // prime order curve where division is allowed
            REllipticCurve curve;
            PRNG  prng(ZeroBlock);


            if (bn_is_prime(curve.getOrder()) == false)
                throw UnitTestFail("this code expects a prime order curve");

            REccNumber one(1);
            if (one != one / one)
            {
                std::cout << one << std::endl;
                std::cout << one / one << std::endl;
                throw UnitTestFail("1 != 1 / 1");
            }

            REccNumber rand(prng), r;
            auto inv = rand.inverse();
            auto prod = rand * inv;
            if (prod != 1)
            {
                std::cout << " rand " << rand << std::endl;
                std::cout << " inv  " << inv << std::endl;
                std::cout << " prod " << prod << std::endl;
                throw std::runtime_error("x * x^-1 != 1 " LOCATION);
            }

            REccNumber a(prng);
            REccNumber b(prng);

            if (a == b)
                throw UnitTestFail(LOCATION);

            auto c = a * b;

            if (b != c / a)
                throw UnitTestFail(LOCATION);
            if (a != c / b)
                throw UnitTestFail(LOCATION);

        }

        {
            REllipticCurve curve;


            for (i32 i = 1; i < 10; ++i)
            {
                if (REccNumber(-i) * (i + 10) != -(i * (i + 10)))
                    throw UnitTestFail(LOCATION);

                if (REccNumber(-i) <= i)
                    throw UnitTestFail(LOCATION);

                if (REccNumber(-1) < i)
                    throw UnitTestFail(LOCATION);

                if((REccNumber(0) += i) != i)
                    throw UnitTestFail(LOCATION);

                if ((REccNumber(0) -= i) != -i)
                    throw UnitTestFail(LOCATION);

                if ((REccNumber(0) += -i) != -i)
                    throw UnitTestFail(LOCATION);

                if ((REccNumber(0) -= -i) != i)
                    throw UnitTestFail(LOCATION);

                if ((REccNumber(0) + i) != i)
                    throw UnitTestFail(LOCATION);

                if ((REccNumber(0) - i) != -i)
                    throw UnitTestFail(LOCATION);

                if ((REccNumber(0) + -i) != -i)
                    throw UnitTestFail(LOCATION);

                if ((REccNumber(0) - -i) != i)
                    throw UnitTestFail(LOCATION);

            }
        }

    }



    void REccpPoint_Test()
    {

        {

            REllipticCurve curve;

            PRNG prng(ZeroBlock);

            REccNumber one(1);
            REccNumber zero(0);

            const auto g = curve.getGenerator();

            //auto g2 = curve.getGenerators()[1] + curve.getGenerators()[2];
            //EccBrick g2Brick(g2);
            //std::cout << "g            " << g << std::endl;


            //for (u64 i = 0; i < 24 * 2; ++i)
            //{
            //    std::cout << "g^"<< i<<"         " << g  * (one * i)<< std::endl;
            //}
            //std::cout << "order        " << order << std::endl;
            //std::cout << "g^(order-1)  " << g*(order - 1) << std::endl;
            //std::cout << "g^order      " << g*order << std::endl;
            //std::cout << "g^(1)        " << g*(one) << std::endl;
            //std::cout << "g^(order+1)  " << g*(order + 1) << std::endl;
            //std::cout << "g^(2)        " << g*(one + one) << std::endl;

            if (g * (curve.getOrder() + 1) != g)
            {
                std::cout << "g^(n+1) != g" << std::endl;
                std::cout << g * (curve.getOrder() + 1) << std::endl;
                std::cout << g << std::endl;
                throw    UnitTestFail("g^(n+1) != g");
            }



            REccNumber a;
            REccNumber b;
            REccNumber r;

            a.randomize(prng);
            b.randomize(prng);
            r.randomize(prng);


            auto a_br = a + b * r;



            auto ga = g * a;

            auto gbr = ((g * b) * r);
            auto gbr2 = g * (b * r);


            //std::cout << "mod  " << curve.getOrder() << std::endl;
            //std::cout << "a    " << a << std::endl;
            //std::cout << "b    " << b << std::endl;
            //std::cout << "r    " << r << std::endl;
            //std::cout << "abr   " << a_br << std::endl;
            //std::cout << "ga  " << ga << std::endl;
            //std::cout << "gbr  " << gbr << std::endl;
            //std::cout << "gbr2 " << gbr2 << std::endl;

            auto ga_br = ga + gbr;
            auto ga_br2 = ga + gbr2;
            auto ga_br3 = g * a_br;

            if (ga_br != ga_br2 || ga_br != ga_br3)
            {
                std::cout << "ga_br != ga_br2" << std::endl;
                std::cout << ga_br << std::endl;
                std::cout << ga_br2 << std::endl;
                std::cout << ga_br3 << std::endl;

                throw UnitTestFail("ga_br != ga_br2");
            }

            auto gBrick(g);

            auto gBOne = gBrick * one;

            if (g != gBOne)
            {
                std::cout << "g     " << g << std::endl;
                std::cout << "gBOne " << gBOne << std::endl;

                throw UnitTestFail("ga != gBa");
            }

            auto gBa = gBrick * a;

            if (ga != gBa)
            {
                std::cout << "ga  " << ga << std::endl;
                std::cout << "gBa " << gBa << std::endl;

                throw UnitTestFail("ga != gBa");
            }
            auto gBbr = ((gBrick * b) * r);
            auto gBbr2 = (gBrick * (b * r));

            auto gBa_br = gBa + gBbr;
            auto gBa_br2 = gBa + gBbr2;


            if (gBa_br != gBa_br2 || gBa_br != ga_br2)
            {
                std::cout << "gBa_br  " << gBa_br << std::endl;
                std::cout << "gBa_br2 " << gBa_br2 << std::endl;
                std::cout << "ga_br2  " << ga_br2 << std::endl;

                throw UnitTestFail("gBa_br != gBa_br2");
            }


            {
                for (u64 i = 0; i < 16; ++i)
                {

                    PRNG prng(toBlock(i), 8);

                    REccPoint p0(prng);
                    REccPoint p1(prng);

                    if (p0 == p1)
                    {
                        throw UnitTestFail(LOCATION);
                    }
                }
            }

        }
    }
#else

void REccpNumber_Test()
{
    throw UnitTestSkipped("ENABLE_RELIC not defined.");
}
void REccpPoint_Test()
{
    throw UnitTestSkipped("ENABLE_RELIC not defined.");
}
#endif


}