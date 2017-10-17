#pragma once
#include <boost/asio.hpp>
#include <cryptoTools/Common/Defines.h>

namespace osuCrypto
{


    class SocketInterface
    {
    public:

        //////////////////////////////////   REQUIRED //////////////////////////////////

        // REQURIED: must implement a distructor as it will be called via the SocketInterface
        virtual ~SocketInterface() = 0;


        // REQURIED: Sends one or more buffers of data over the socket. See SocketAdapter<T> for an example.
        // @buffers [input]: is the vector of buffers that should be sent.
        // @error [output]:   indicates what soemthing went wrong.
        // @bytesTransfered [output]: the number of bytes that were sent.
        //         should be all the buffers sizes but is some cases it may not be.
        virtual void send(span<boost::asio::mutable_buffer> buffers, bool& error, u64& bytesTransfered) = 0;

        // REQURIED: Receive one or more buffers of data over the socket. See SocketAdapter<T> for an example.
        // @buffers [output]: is the vector of buffers that should be sent.
        // @error [output]:   indicates what soemthing went wrong.
        // @bytesTransfered [output]: the number of bytes that were sent.
        //         should be all the buffers sizes but is some cases it may not be.
        virtual void recv(span<boost::asio::mutable_buffer> buffers, bool& error, u64& bytesTransfered) = 0;


        //////////////////////////////////   OPTIONAL //////////////////////////////////

        // OPTIONAL -- no-op close is default. Will be called when all Channels that refernece it are destructed/
        virtual void close() {};

        // OPTIONAL -- default implementation of async_recv is synchronous
        // @buffers [output]: is the vector of buffers that should be sent.
        // @fn [input]:   A call back that should be called on completion of the IO
        virtual void async_recv(span<boost::asio::mutable_buffer> buffers, const std::function<void(const boost::system::error_code&, u64 bytesTransfered)>& fn)
        {
            bool error;
            u64 bytesTransfered;
            recv(buffers, error, bytesTransfered);
            auto ec = error ? boost::system::errc::make_error_code(boost::system::errc::io_error) : boost::system::errc::make_error_code(boost::system::errc::success);
            fn(ec, bytesTransfered);
        };

        // OPTIONAL -- default implementation of async_send is synchronous
        // @buffers [input]: is the vector of buffers that should be sent.
        // @fn [input]:   A call back that should be called on completion of the IO
        virtual void async_send(span<boost::asio::mutable_buffer> buffers, const std::function<void(const boost::system::error_code&, u64 bytesTransfered)>& fn)
        {
            bool error;
            u64 bytesTransfered;
            send(buffers, error, bytesTransfered);
            auto ec = error ? boost::system::errc::make_error_code(boost::system::errc::io_error) : boost::system::errc::make_error_code(boost::system::errc::success);
            fn(ec, bytesTransfered);
        };


    };


    template<typename T>
    class SocketAdapter : public SocketInterface
    {
    public:
        T& mChl;

        SocketAdapter(T& chl)
            :mChl(chl)
        {}

        ~SocketAdapter() override
        {
        }

        void send(span<boost::asio::mutable_buffer> buffers, bool& error, u64& bytesTransfered) override
        {
            bytesTransfered = 0;
            for (u64 i = 0; i < u64( buffers.size()); ++i) {
                try {
                    // Use boost conversions to get normal pointer size
                    auto data = boost::asio::buffer_cast<u8*>(buffers[i]);
                    auto size = boost::asio::buffer_size(buffers[i]);

                    // may throw
                    mChl.send(data, size);
                    bytesTransfered += size;
                }
                catch (...) {
                    error = true;
                    return;
                }
            }
            error = false;
        }

        void recv(span<boost::asio::mutable_buffer> buffers, bool& error, u64& bytesTransfered) override
        {
            bytesTransfered = 0;
            for (u64 i = 0; i < u64(buffers.size()); ++i) {
                try {
                    // Use boost conversions to get normal pointer size
                    auto data = boost::asio::buffer_cast<u8*>(buffers[i]);
                    auto size = boost::asio::buffer_size(buffers[i]);

                    // may throw
                    mChl.recv(data, size);
                    bytesTransfered += size;
                }
                catch (...) {
                    error = true;
                    return;
                }
            }
            error = false;
        }
    };




    class BoostSocketInterface : public SocketInterface
    {
    public:
        boost::asio::ip::tcp::socket mSock;

        BoostSocketInterface(boost::asio::ip::tcp::socket&& ios)
            : mSock(std::move(ios))
        {
            //std::cout << IoStream::lock << "create " << this << std::endl << IoStream::unlock;
        }

        ~BoostSocketInterface() override
        {
            //std::cout << IoStream::lock << "destoy " << this << std::endl << IoStream::unlock;

            close();
        }

        void close() override {
			boost::system::error_code ec;
			mSock.close(ec);
			if (ec) std::cout <<"BoostSocketInterface::close() error: "<< ec.message() << std::endl; 
		}

        void async_recv(span<boost::asio::mutable_buffer> buffers, const std::function<void(const boost::system::error_code&, u64 bytesTransfered)>& fn) override
        {
            boost::asio::async_read(mSock, buffers, fn);
        }

        void async_send(span<boost::asio::mutable_buffer> buffers, const std::function<void(const boost::system::error_code&, u64 bytesTransfered)>& fn) override
        {
            boost::asio::async_write(mSock, buffers, fn);
        }

        void send(span<boost::asio::mutable_buffer> buffers, bool& error, u64& bytesTransfered) override
        {
            boost::system::error_code ec;
            bytesTransfered = boost::asio::write(mSock, buffers, ec);
            error = (ec != 0);
        }

        void recv(span<boost::asio::mutable_buffer> buffers, bool& error, u64& bytesTransfered) override
        {
            boost::system::error_code ec;
            bytesTransfered = boost::asio::read(mSock, buffers, ec);
            error = (ec != 0);
        }
    };
}
