
#include <cryptoTools/Common/CLP.h>

namespace tests_cryptoTools
{


    void BtNetwork_Connect1_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_BadConnect_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_shutdown_test(const osuCrypto::CLP& cmd);


    void BtNetwork_RapidConnect_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_OneMegabyteSend_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_ConnectMany_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_CrossConnect_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_ManySessions_Test(const osuCrypto::CLP& cmd);


    void BtNetwork_AsyncConnect_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_std_Containers_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_bitVector_Test(const osuCrypto::CLP& cmd);


    void BtNetwork_recvErrorHandler_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_closeOnError_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_clientClose_Test(const osuCrypto::CLP& cmd);


	void BtNetwork_SocketInterface_Test(const osuCrypto::CLP& cmd);

	void BtNetwork_AnonymousMode_Test(const osuCrypto::CLP& cmd);
	void BtNetwork_ServerMode_Test(const osuCrypto::CLP& cmd);
	void BtNetwork_CancelChannel_Test(const osuCrypto::CLP& cmd);


    void BtNetwork_oneWorker_Test(const osuCrypto::CLP& cmd);
    void BtNetwork_useAfterCancel_test(const osuCrypto::CLP& cmd);
    void BtNetwork_fastCancel(const osuCrypto::CLP&cmd);

    void SBO_ptr_test();
    void BtNetwork_queue_Test(const osuCrypto::CLP& cmd);
}