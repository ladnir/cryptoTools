#include <cryptoTools/Common/Log.h>
#include <functional>

#include "tests_cryptoTools/AES_Tests.h"
#include "tests_cryptoTools/Rijndael256_Tests.h"
#include "tests_cryptoTools/BtChannel_Tests.h"
#include "tests_cryptoTools/REcc_Tests.h"
#include "tests_cryptoTools/Misc_Tests.h"
#include "tests_cryptoTools/Cuckoo_Tests.h"
#include "tests_cryptoTools/Circuit_Tests.h"
#include "UnitTests.h"
#include "tests_cryptoTools/block_Tests.h"
#include "tests_cryptoTools/MxCircuit_Tests.h"
#include "tests_cryptoTools/WolfSSL_Tests.h"

#include <cryptoTools/Common/config.h>
using namespace osuCrypto;

namespace tests_cryptoTools
{
    TestCollection Tests([](TestCollection& th) {

#ifdef ENABLE_BOOST
        th.add("BtNetwork_SBO_ptr_test                  ", SBO_ptr_test);
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
        th.add("BtNetwork_PartialConnect_Test           ", BtNetwork_PartialConnect_Test);
        
        th.add("BtNetwork_oneWorker_Test                ", BtNetwork_oneWorker_Test);
        th.add("BtNetwork_queue_Test                    ", BtNetwork_queue_Test);
        th.add("BtNetwork_socketAdapter_test            ", BtNetwork_socketAdapter_test);
        th.add("BtNetwork_BasicSocket_test              ", BtNetwork_BasicSocket_test);
#endif

        th.add("block_operation_test                    ", block_operation_test);
        th.add("AES                                     ", AES_EncDec_Test);
#ifdef OC_ENABLE_AESNI
        th.add("Rijndael256                             ", Rijndael256_EncDec_Test);
#endif // ENABLE_AESNI

        th.add("BitVector_Indexing_Test                 ", BitVector_Indexing_Test_Impl);
        th.add("BitVector_Parity                        ", BitVector_Parity_Test_Impl);
        th.add("BitVector_Append_Test                   ", BitVector_Append_Test_Impl);
        th.add("BitVector_Copy_Test                     ", BitVector_Copy_Test_Impl);
        th.add("BitVector_Resize_Test                   ", BitVector_Resize_Test_Impl);
        
        th.add("CuckooIndex_many_Test                   ", CuckooIndex_many_Test_Impl);
        th.add("CuckooIndex_paramSweep_Test             ", CuckooIndex_paramSweep_Test_Impl);
        th.add("CuckooIndex_parallel_Test               ", CuckooIndex_parallel_Test_Impl);

        th.add("REccpNumber_Test                        ", REccpNumber_Test);
        th.add("REccpPoint_Test                         ", REccpPoint_Test);


        th.add("BetaCircuit_SequentialOp_Test           ", BetaCircuit_SequentialOp_Test);
        th.add("BetaCircuit_int_Adder_Test              ", BetaCircuit_int_Adder_Test);
        th.add("BetaCircuit_int_Adder_const_Test        ", BetaCircuit_int_Adder_const_Test);
        th.add("BetaCircuit_int_Subtractor_Test         ", BetaCircuit_int_Subtractor_Test);
        th.add("BetaCircuit_int_Subtractor_const_Test   ", BetaCircuit_int_Subtractor_const_Test);
        th.add("BetaCircuit_uint_Adder_Test             ", BetaCircuit_uint_Adder_Test);
        th.add("BetaCircuit_uint_Subtractor_Test        ", BetaCircuit_uint_Subtractor_Test);
        th.add("BetaCircuit_int_Multiply_Test           ", BetaCircuit_int_Multiply_Test);
        th.add("BetaCircuit_uint_Multiply_Test          ", BetaCircuit_uint_Multiply_Test);
        
        th.add("BetaCircuit_int_LessThan_Test           ", BetaCircuit_int_LessThan_Test);
        th.add("BetaCircuit_int_GreaterThanEq_Test      ", BetaCircuit_int_GreaterThanEq_Test);
        th.add("BetaCircuit_uint_LessThan_Test          ", BetaCircuit_uint_LessThan_Test);
        th.add("BetaCircuit_uint_GreaterThanEq_Test     ", BetaCircuit_uint_GreaterThanEq_Test);
        th.add("BetaCircuit_negate_Test                 ", BetaCircuit_negate_Test);
        th.add("BetaCircuit_bitInvert_Test              ", BetaCircuit_bitInvert_Test);
        th.add("BetaCircuit_removeSign_Test             ", BetaCircuit_removeSign_Test);
        th.add("BetaCircuit_addSign_Test                ", BetaCircuit_addSign_Test);

        th.add("BetaCircuit_int_Divide_Test             ", BetaCircuit_int_Divide_Test);
        th.add("BetaCircuit_multiplex_Test              ", BetaCircuit_multiplex_Test);
        //th.add("BetaCircuit_int_piecewise_Test          ", BetaCircuit_int_piecewise_Test);
        th.add("BetaCircuit_json_Tests                  ", BetaCircuit_json_Tests);
        th.add("BetaCircuit_bin_Tests                   ", BetaCircuit_bin_Tests);
        th.add("BetaCircuit_xor_and_lvl_test            ", BetaCircuit_xor_and_lvl_test);
        
        th.add("BetaCircuit_aes_test                    ", BetaCircuit_aes_test);
        //th.add("BetaCircuit_aes_sbox_test               ", BetaCircuit_aes_sbox_test);
        //th.add("BetaCircuit_aes_shiftRows_test          ", BetaCircuit_aes_shiftRows_test);
        //th.add("BetaCircuit_aes_mixColumns_test         ", BetaCircuit_aes_mixColumns_test);


        th.add("MxCircuit_Bit_Ops_Test                  ", MxCircuit_Bit_Ops_Test);
        th.add("MxCircuit_BInt_Ops_Test                 ", MxCircuit_BInt_Ops_Test);
        th.add("MxCircuit_BUInt_Ops_Test                ", MxCircuit_BUInt_Ops_Test);
        th.add("MxCircuit_BDynInt_Ops_Test              ", MxCircuit_BDynInt_Ops_Test);
        th.add("MxCircuit_BDynUInt_Ops_Test             ", MxCircuit_BDynUInt_Ops_Test);
        th.add("MxCircuit_Cast_Test                     ", MxCircuit_Cast_Test);
        th.add("MxCircuit_asBetaCircuit_Test            ", MxCircuit_asBetaCircuit_Test);
        th.add("MxCircuit_parallelPrefix_Test           ", MxCircuit_parallelPrefix_Test);
        th.add("MxCircuit_rippleAdder_Test              ", MxCircuit_rippleAdder_Test);
        th.add("MxCircuit_parallelSummation_Test        ", MxCircuit_parallelSummation_Test);
        th.add("MxCircuit_multiply_Test                 ", MxCircuit_multiply_Test);
        th.add("MxCircuit_divideRemainder_Test         ", MxCircuit_divideRemainder_Test);
        
        
        
        });



}
