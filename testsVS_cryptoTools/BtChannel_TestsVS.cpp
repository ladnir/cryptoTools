#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Common.h"
#include "BtChannel_Tests.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace tests_cryptoTools
{
    TEST_CLASS(BtNetworking_Tests)
    {
    public:

		TEST_METHOD(BtNetwork_CancelChannel_TestVS)
		{
			InitDebugPrinting();
			BtNetwork_CancelChannel_Test();
		}

		TEST_METHOD(BtNetwork_ServerMode_TestVS)
		{
			InitDebugPrinting();
			BtNetwork_ServerMode_Test();
		}

		TEST_METHOD(BtNetwork_AnonymousMode_TestVS)
		{
			InitDebugPrinting();
			BtNetwork_AnonymousMode_Test();
		}

        TEST_METHOD(BtNetwork_Connect1_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_Connect1_Test();
        }


        TEST_METHOD(BtNetwork_OneMegabyteSend_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_OneMegabyteSend_Test();
        }

		 
        TEST_METHOD(BtNetwork_ConnectMany_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_ConnectMany_Test();
        }


        TEST_METHOD(BtNetwork_CrossConnect_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_CrossConnect_Test();
        }


        TEST_METHOD(BtNetwork_ManySessions_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_ManySessions_Test();
        }

        TEST_METHOD(BtNetwork_AsyncConnect_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_AsyncConnect_Test();
        }
        TEST_METHOD(BtNetwork_std_Containers_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_std_Containers_Test();
        }
        TEST_METHOD(BtNetwork_recvError_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_recvErrorHandler_Test();
        }

        TEST_METHOD(BtNetwork_closeOnError_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_closeOnError_Test();
        }

        TEST_METHOD(BtNetwork_bitVector_TestVS)
        {
            InitDebugPrinting();
            BtNetwork_bitVector_Test();
        }

		TEST_METHOD(BtNetwork_SocketInterface_TestVS)
		{
			InitDebugPrinting();
			BtNetwork_SocketInterface_Test();
		}

        TEST_METHOD(SBO_ptr_testVS)
        {
            InitDebugPrinting();
            SBO_ptr_test(); 
        }

    };
}
#endif