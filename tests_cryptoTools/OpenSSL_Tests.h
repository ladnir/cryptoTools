#pragma once
#include <cryptoTools/Common/CLP.h>


void OpenSSL_echoServer_test(const osuCrypto::CLP& cmd);
void OpenSSL_mutualAuth_test(const osuCrypto::CLP& cmd); 
void OpenSSL_channel_test(const osuCrypto::CLP& cmd);
void OpenSSL_CancelChannel_Test();