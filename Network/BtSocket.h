#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "Common/Defines.h"


#include <deque>
#include <mutex>
#include <future> 

#include "Network/BtIOService.h"

namespace osuCrypto { 

    class WinNetIOService;
    class ChannelBuffer;



    //class BtSocket
    //{
    //public:
    //    BtSocket(BtIOService& ios);


    //};

    //inline BtSocket::BtSocket(BtIOService& ios) :
    //    mHandle(ios.mIoService),
    //    mSendStrand(ios.mIoService),
    //    mRecvStrand(ios.mIoService),
    //    mStopped(false),
    //    mOutstandingSendData(0),
    //    mMaxOutstandingSendData(0),
    //    mTotalSentData(0)
    //{}


}
