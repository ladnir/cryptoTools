#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Cuckoo_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace tests_cryptoTools
{
    TEST_CLASS(Cuckoo_Tests)
    {
    public:

        TEST_METHOD(CuckooHasher_many_Test)
        {
            InitDebugPrinting();
            CuckooHasher_many_Test_Impl();
        }
        
        TEST_METHOD(CuckooHasher_paramSweep_Test)
        {
            InitDebugPrinting();
            CuckooHasher_paramSweep_Test_Impl();
        }

        TEST_METHOD(CuckooHasher_parallel_Test)
        {
            InitDebugPrinting();
            CuckooHasher_parallel_Test_Impl();
        }
        TEST_METHOD(CuckooMap_Big_Test)
        {
            InitDebugPrinting();
            CuckooMap_Big_Test_Impl();
        }
        TEST_METHOD(CuckooMap_Small_Test)
        {
            InitDebugPrinting();
            CuckooMap_Small_Test_Impl();
        }        
        TEST_METHOD(CuckooMap_Test)
        {
            InitDebugPrinting();
            CuckooMap_Test_Impl();
        }       
        TEST_METHOD(CuckooMap_old_Test)
        {
            InitDebugPrinting();
            CuckooMap_old_Test_Impl();
        }

    };
}
#endif
