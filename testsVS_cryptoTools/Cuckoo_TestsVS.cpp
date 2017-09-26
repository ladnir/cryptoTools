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

        TEST_METHOD(CuckooIndex_many_Test)
        {
            InitDebugPrinting();
            CuckooIndex_many_Test_Impl();
        }

        TEST_METHOD(CuckooIndex_paramSweep_Test)
        {
            InitDebugPrinting();
            CuckooIndex_paramSweep_Test_Impl();
        }

		TEST_METHOD(CuckooIndex_parallel_Test)
		{
			InitDebugPrinting();
			CuckooIndex_parallel_Test_Impl();
		}

		//TEST_METHOD(CuckooIndexVsCuckooHasherVS)
		//{
		//	InitDebugPrinting();
		//	CuckooIndexVsCuckooHasher();
		//}
    };
}
#endif
