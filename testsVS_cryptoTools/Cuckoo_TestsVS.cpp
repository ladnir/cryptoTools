#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Cuckoo_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace osuCrypto_tests
{
    TEST_CLASS(Cuckoo_Tests)
    {
    public:

        TEST_METHOD(CuckooHasher_Test)
        {
            InitDebugPrinting();
            CuckooHasher_Test_Impl();
        }

        TEST_METHOD(CuckooHasher_parallel_Test)
        {
            InitDebugPrinting();
            CuckooHasher_parallel_Test_Impl();
        }

    };
}
#endif
