#include <cryptoTools/Common/Log.h>
#include <functional>

#include "tests_cryptoTools/AES_Tests.h"
#include "tests_cryptoTools/BtChannel_Tests.h"
#include "tests_cryptoTools/Ecc_Tests.h"
#include "tests_cryptoTools/Misc_Tests.h"
#include "tests_cryptoTools/Cuckoo_Tests.h"
#include "UnitTests.h"


using namespace osuCrypto;

namespace tests_cryptoTools
{
    TestCollection Tests([](TestCollection& th) {
        th.add("BtNetwork_Connect1_Test                 ", BtNetwork_Connect1_Test);
        th.add("BtNetwork_RapidConnect_Test             ", BtNetwork_RapidConnect_Test);
        th.add("BtNetwork_SocketInterface_Test          ", BtNetwork_SocketInterface_Test);
        th.add("BtNetwork_OneMegabyteSend_Test          ", BtNetwork_OneMegabyteSend_Test);
        th.add("BtNetwork_ConnectMany_Test              ", BtNetwork_ConnectMany_Test);
        th.add("BtNetwork_CrossConnect_Test             ", BtNetwork_CrossConnect_Test);
        th.add("BtNetwork_ManySessions_Test             ", BtNetwork_ManySessions_Test);
        th.add("BtNetwork_bitVector_Test                ", BtNetwork_bitVector_Test);
        th.add("BtNetwork_AsyncConnect_Test             ", BtNetwork_AsyncConnect_Test);
        th.add("BtNetwork_std_Containers_Test           ", BtNetwork_std_Containers_Test);
        th.add("BtNetwork_recvErrorHandler_Test         ", BtNetwork_recvErrorHandler_Test);
        th.add("BtNetwork_closeOnError_Test             ", BtNetwork_closeOnError_Test);
        th.add("BtNetwork_AnonymousMode_Test            ", BtNetwork_AnonymousMode_Test);
        th.add("BtNetwork_CancelChannel_Test            ", BtNetwork_CancelChannel_Test);
        th.add("BtNetwork_ServerMode_Test               ", BtNetwork_ServerMode_Test);
        th.add("AES                                     ", AES_EncDec_Test);
        th.add("BitVector_Indexing_Test                 ", BitVector_Indexing_Test_Impl);
        th.add("BitVector_Parity                        ", BitVector_Parity_Test_Impl);
        th.add("BitVector_Append_Test                   ", BitVector_Append_Test_Impl);
        th.add("BitVector_Copy_Test                     ", BitVector_Copy_Test_Impl);
        th.add("CuckooIndex_many_Test_Impl              ", CuckooIndex_many_Test_Impl);
        th.add("CuckooIndex_paramSweep_Test_Impl        ", CuckooIndex_paramSweep_Test_Impl);
        th.add("CuckooIndex_parallel_Test_Impl          ", CuckooIndex_parallel_Test_Impl);
        th.add("Ecc2mNumber_Test                        ", Ecc2mNumber_Test);
        th.add("Ecc2mPoint_Test                         ", Ecc2mPoint_Test);
        th.add("EccpNumber_Test                         ", EccpNumber_Test);
        th.add("EccpPoint_Test                          ", EccpPoint_Test);
        th.add("SBO_ptr_test                            ", SBO_ptr_test);
    });



}