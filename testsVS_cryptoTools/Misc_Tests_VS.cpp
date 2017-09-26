#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Misc_Tests.h"

//
//void BitVector_Indexing_Test_Impl();
//void BitVector_Parity_Test_Impl();
//void BitVector_Append_Test_Impl();
//void BitVector_Copy_Test_Impl();

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace tests_cryptoTools
{
    TEST_CLASS(LocalChannel_Tests)
    {
    public:

        TEST_METHOD(BitVector_Indexing_Test)
        {
            BitVector_Indexing_Test_Impl();
        }

        TEST_METHOD(BitVector_Parity_Test)
        {
            BitVector_Parity_Test_Impl();
        }

        TEST_METHOD(BitVector_Append_Test)
        {
            BitVector_Append_Test_Impl();
        }

        TEST_METHOD(BitVector_Copy_Test)
        {
            BitVector_Copy_Test_Impl();
        }

    };
}
#endif
