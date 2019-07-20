#include "IoBuffer.h"
#include "Channel.h"
#include <sstream>
#include <exception>

namespace osuCrypto
{
    namespace details
    {
        operation_canceled opCancel;

        void FixedSendBuff::asyncPerform(ChannelBase * base, io_completion_handle&& completionHandle)
        {
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
            base->mHandle->async_recv({&base->mRecvBuffer, 1}, [this](const error_code& ec, u64 bytesTransferred) {

				mBase->mTotalRecvData += bytesTransferred;

                if (!mComHandle)
                    throw std::runtime_error(LOCATION);

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
                            mBase->setBadRecvErrorState(ss.str());

                            // give the user a chance to give us another location 
                            // by passing out an exception which they can call.
                            mPromise.set_exception(std::make_exception_ptr(
                                BadReceiveBufferSize(ss.str(), getHeaderSize(), [this](u8* dest)
                            {
                                bool error;
                                u64 bytesTransferred;

                                // clear the receive error.
                                mBase->clearBadRecvErrorState();

                                // perform the write.
                                mBase->mRecvBuffer = boost::asio::buffer(dest, getHeaderSize());
                                mBase->mHandle->recv({ &mBase->mRecvBuffer, 1 }, error, bytesTransferred);

                                // convert the return value to an error_code and call 
                                // the completion handle.
                                auto ec = error
                                    ? boost::system::errc::make_error_code(boost::system::errc::io_error)
                                    : boost::system::errc::make_error_code(boost::system::errc::success);
                                mComHandle(ec, bytesTransferred);
                            })));

                            return;
                        }
                    }

                    // the normal case that the buffer is the right size or was correctly resized.
                    mBase->mRecvBuffer = getRecvBuffer();
                    mBase->mHandle->async_recv({ &mBase->mRecvBuffer , 1 }, [this](const error_code& ec, u64 bt)
                    {

                        if (!ec) mPromise.set_value();
                        else mPromise.set_exception(std::make_exception_ptr(std::runtime_error(LOCATION)));
                        
                        if (!mComHandle)
                            throw std::runtime_error(LOCATION);

                        mComHandle(ec, bt);
                    });
                }
                else
                {

                    mComHandle(ec, bytesTransferred);

                }
            });

        }
        std::string RecvOperation::toString() const
        {
            return std::string("RecvOperation #") 
#ifdef CHANNEL_LOGGING
                + std::to_string(mIdx)
#endif
                ;
        }
        std::string SendOperation::toString() const
        {
            return std::string("SendOperation #") 
#ifdef CHANNEL_LOGGING
                + std::to_string(mIdx)
#endif
                ;
        }

        std::string FixedSendBuff::toString() const
        {
            return std::string("FixedSendBuff #")
#ifdef CHANNEL_LOGGING
                + std::to_string(mIdx) 
#endif
                + " ~ " + std::to_string(getBufferSize()) + " bytes";
        }

        std::string FixedRecvBuff::toString() const
        {
            return std::string("FixedRecvBuff #") 
#ifdef CHANNEL_LOGGING
                + std::to_string(mIdx) 
#endif
                + " ~ " + std::to_string(getBufferSize()) + " bytes";
        }

        
    }
}
