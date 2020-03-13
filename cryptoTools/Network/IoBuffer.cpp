#include <cryptoTools/Common/config.h>
#ifdef ENABLE_BOOST

#include "IoBuffer.h"
#include "Channel.h"
#include "IOService.h"
#include <sstream>
#include <exception>

namespace osuCrypto
{
    namespace details
    {
        //operation_canceled opCancel;

        void FixedSendBuff::asyncPerform(ChannelBase * base, io_completion_handle&& completionHandle)
        {
            //if (base->mHandle == nullptr)
            //{
            //    lout << "null handle" << std::endl;

            //    lout << base->mLog << std::endl;
            //}

            base->mSendBuffers = getSendBuffer();
            base->mHandle->async_send(base->mSendBuffers, 
                std::forward<io_completion_handle>(completionHandle));
        }

        void FixedRecvBuff::asyncPerform(ChannelBase * base, io_completion_handle&& completionHandle)
        {

            mComHandle = std::move(completionHandle);
            mBase = base;

            if (!mComHandle)
                throw std::runtime_error(LOCATION);

            // first we have to receive the header which tells us how much.
            base->mRecvBuffer = getRecvHeaderBuffer();
            base->mHandle->async_recv({&base->mRecvBuffer, 1}, [this](const error_code& ec, u64 bt1) {
                
                if (!ec)
                {
                    // check that the buffer has enough space. Resize if not.
                    if (getHeaderSize() != getBufferSize())
                    {
                        resizeBuffer(getHeaderSize());

                        // check that the resize was successful.
                        if (getHeaderSize() != getBufferSize())
                        {
                            std::stringstream ss;
                            ss << "Bad receive buffer size.\n"
                                <<         "  Size transmitted: " << getHeaderSize()
                                << " bytes\n  Size of buffer:   " << getBufferSize() << " bytes\n";

                            // make the channel to know that a receive has a partial failure.
                            // The partial error can be cleared if the following lambda is 
                            // called by the user. This will complete the receive operation.
                            //mBase->setBadRecvErrorState(ss.str());

                            // give the user a chance to give us another location 
                            // by passing out an exception which they can call.
                            mPromise.set_exception(std::make_exception_ptr(
                                BadReceiveBufferSize(ss.str(), getHeaderSize())));

                            auto ec = boost::system::errc::make_error_code(boost::system::errc::no_buffer_space);
                            mComHandle(ec, sizeof(u32));
                            return;
                        }
                    }

                    // the normal case that the buffer is the right size or was correctly resized.
                    mBase->mRecvBuffer = getRecvBuffer();
                    mBase->mHandle->async_recv({ &mBase->mRecvBuffer , 1 }, [this, bt1](const error_code& ec, u64 bt2)
                    {

                        if (!ec) mPromise.set_value();
                        else mPromise.set_exception(std::make_exception_ptr(std::runtime_error(ec.message())));
                        
                        if (!mComHandle)
                            throw std::runtime_error(LOCATION);

#ifdef ENABLE_NET_LOG
                        if(ec)
                            log("FixedRecvBuff error " + std::to_string(mIdx) + "   " +  LOCATION);
                        else
                            log("FixedRecvBuff success " + std::to_string(mIdx) + "   " + LOCATION);

#endif
                        mComHandle(ec, bt1 + bt2);
                    });
                }
                else
                {
#ifdef ENABLE_NET_LOG
                    log("FixedRecvBuff error " + std::to_string(mIdx) + " " + ec.message() +"  " + LOCATION);
#endif
                    mPromise.set_exception(std::make_exception_ptr(std::runtime_error(ec.message())));
                    mComHandle(ec, bt1);
                }
            });

        }


        std::string FixedSendBuff::toString() const
        {
            return std::string("FixedSendBuff #")
#ifdef ENABLE_NET_LOG
                + std::to_string(mIdx) 
#endif
                + " ~ " + std::to_string(getBufferSize()) + " bytes";
        }

        std::string FixedRecvBuff::toString() const
        {
            return std::string("FixedRecvBuff #") 
#ifdef ENABLE_NET_LOG
                + std::to_string(mIdx) 
#endif
                + " ~ " + std::to_string(getBufferSize()) + " bytes";
        }

        
        //void Callback::asyncPerform(ChannelBase* base, io_completion_handle&& completionHandle)
        //{
        //    auto ec = boost::system::errc::make_error_code(boost::system::errc::success);
        //    boost::asio::post(base->mIos.mIoService.get_executor(), [c = std::move(mComm), ec](){
        //        c(ec);
        //    });
        //    completionHandle(ec, 0);
        //}

        boost::asio::io_context& getIOService(ChannelBase* base)
        {
            return base->mIos.mIoService;
        }

    }
}
#endif