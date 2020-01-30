#include <cryptoTools/Common/Log.h>
#include <functional>

#include "tests_cryptoTools/AES_Tests.h"
#include "tests_cryptoTools/BtChannel_Tests.h"
#include "tests_cryptoTools/Ecc_Tests.h"
#include "tests_cryptoTools/REcc_Tests.h"
#include "tests_cryptoTools/Misc_Tests.h"
#include "tests_cryptoTools/Cuckoo_Tests.h"
#include "tests_cryptoTools/Circuit_Tests.h"
#include "UnitTests.h"

#include "tests_cryptoTools/WolfSSL_Tests.h"

using namespace osuCrypto;

namespace tests_cryptoTools
{
    TestCollection Tests([](TestCollection& th) {
        th.add("BtNetwork_Connect1_Test                 ", BtNetwork_Connect1_Test);
        th.add("BtNetwork_RapidConnect_Test             ", BtNetwork_RapidConnect_Test);
        th.add("BtNetwork_shutdown_test                 ", BtNetwork_shutdown_test);
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
        th.add("BtNetwork_useAfterCancel_test           ", BtNetwork_useAfterCancel_test);
        
        th.add("BtNetwork_fastCancel                    ", BtNetwork_fastCancel);
        th.add("BtNetwork_ServerMode_Test               ", BtNetwork_ServerMode_Test);
        th.add("BtNetwork_clientClose_Test              ", BtNetwork_clientClose_Test);
        th.add("BtNetwork_BadConnect_Test               ", BtNetwork_BadConnect_Test);
        th.add("BtNetwork_oneWorker_Test                ", BtNetwork_oneWorker_Test);
        th.add("BtNetwork_queue_Test                    ",BtNetwork_queue_Test);
        
        th.add("wolfSSL_echoServer_test                 ", wolfSSL_echoServer_test);
        th.add("wolfSSL_mutualAuth_test                 ", wolfSSL_mutualAuth_test);
        th.add("wolfSSL_channel_test                    ", wolfSSL_channel_test);
        th.add("wolfSSL_CancelChannel_Test              ", wolfSSL_CancelChannel_Test);

        th.add("AES                                     ", AES_EncDec_Test);

        th.add("BitVector_Indexing_Test                 ", BitVector_Indexing_Test_Impl);
        th.add("BitVector_Parity                        ", BitVector_Parity_Test_Impl);
        th.add("BitVector_Append_Test                   ", BitVector_Append_Test_Impl);
        th.add("BitVector_Copy_Test                     ", BitVector_Copy_Test_Impl);
        th.add("BitVector_Resize_Test                   ", BitVector_Resize_Test_Impl);
        
        //th.add("CuckooIndex_many_Test                   ", CuckooIndex_many_Test_Impl);
        //th.add("CuckooIndex_paramSweep_Test             ", CuckooIndex_paramSweep_Test_Impl);
        //th.add("CuckooIndex_parallel_Test               ", CuckooIndex_parallel_Test_Impl);

        th.add("Ecc2mNumber_Test                        ", Ecc2mNumber_Test);
        th.add("Ecc2mPoint_Test                         ", Ecc2mPoint_Test);
        th.add("EccpNumber_Test                         ", EccpNumber_Test);
        th.add("EccpPoint_Test                          ", EccpPoint_Test);
        th.add("REccpNumber_Test                        ", REccpNumber_Test);
        th.add("REccpPoint_Test                         ", REccpPoint_Test);

        th.add("SBO_ptr_test                            ", SBO_ptr_test);

#ifdef ENABLE_CIRCUITS
        th.add("BetaCircuit_SequentialOp_Test           ", BetaCircuit_SequentialOp_Test);
        th.add("BetaCircuit_int_Adder_Test              ", BetaCircuit_int_Adder_Test);
        th.add("BetaCircuit_int_Adder_const_Test        ", BetaCircuit_int_Adder_const_Test);
        th.add("BetaCircuit_int_Subtractor_Test         ", BetaCircuit_int_Subtractor_Test);
        th.add("BetaCircuit_int_Subtractor_const_Test   ", BetaCircuit_int_Subtractor_const_Test);
        th.add("BetaCircuit_uint_Adder_Test             ", BetaCircuit_uint_Adder_Test);
        th.add("BetaCircuit_uint_Subtractor_Test        ", BetaCircuit_uint_Subtractor_Test);
        th.add("BetaCircuit_int_Multiply_Test           ", BetaCircuit_int_Multiply_Test);
        th.add("BetaCircuit_uint_Multiply_Test          ", BetaCircuit_uint_Multiply_Test);
        th.add("BetaCircuit_int_Divide_Test             ", BetaCircuit_int_Divide_Test);
        th.add("BetaCircuit_int_LessThan_Test           ", BetaCircuit_int_LessThan_Test);
        th.add("BetaCircuit_int_GreaterThanEq_Test      ", BetaCircuit_int_GreaterThanEq_Test);
        th.add("BetaCircuit_uint_LessThan_Test          ", BetaCircuit_uint_LessThan_Test);
        th.add("BetaCircuit_uint_GreaterThanEq_Test     ", BetaCircuit_uint_GreaterThanEq_Test);
        th.add("BetaCircuit_multiplex_Test              ", BetaCircuit_multiplex_Test);
        th.add("BetaCircuit_negate_Test                 ", BetaCircuit_negate_Test);
        th.add("BetaCircuit_bitInvert_Test              ", BetaCircuit_bitInvert_Test);
        th.add("BetaCircuit_removeSign_Test             ", BetaCircuit_removeSign_Test);
        th.add("BetaCircuit_addSign_Test                ", BetaCircuit_addSign_Test);
        //th.add("BetaCircuit_int_piecewise_Test          ", BetaCircuit_int_piecewise_Test);
        th.add("BetaCircuit_json_Tests                  ", BetaCircuit_json_Tests);
        th.add("BetaCircuit_bin_Tests                   ", BetaCircuit_bin_Tests);

        th.add("BetaCircuit_aes_test                    ", BetaCircuit_aes_test);
        //th.add("BetaCircuit_aes_sbox_test               ", BetaCircuit_aes_sbox_test);
        //th.add("BetaCircuit_aes_shiftRows_test          ", BetaCircuit_aes_shiftRows_test);
        //th.add("BetaCircuit_aes_mixColumns_test         ", BetaCircuit_aes_mixColumns_test);
#endif
    });



}