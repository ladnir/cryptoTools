#pragma once
#include <boost/asio.hpp>
#include <cryptoTools/Common/Defines.h>
#include "IoBuffer.h"

namespace osuCrypto
{


    class SocketInterface
    {
    public:

        //////////////////////////////////   REQUIRED //////////////////////////////////

        // REQURIED: must implement a distructor as it will be called via the SocketInterface
        virtual ~SocketInterface() {};


        // REQUIRED -- buffers contains a list of buffers that are allocated
        // by the caller. The callee should recv data into those buffers. The
        // callee should take a move of the callback fn. When the IO is complete
        // the callee should call the callback fn.
        // @buffers [output]: is the vector of buffers that should be recved.
        // @fn [input]:   A call back that should be called on completion of the IO.
        virtual void async_recv(
            span<boost::asio::mutable_buffer> buffers, 
            io_completion_handle&& fn) = 0;

        // REQUIRED -- buffers contains a list of buffers that are allocated
        // by the caller. The callee should send the data in those buffers. The
        // callee should take a move of the callback fn. When the IO is complete
        // the callee should call the callback fn.
        // @buffers [input]: is the vector of buffers that should be sent.
        // @fn [input]:   A call back that should be called on completion of the IO
        virtual void async_send(span<boost::asio::mutable_buffer> buffers, io_completion_handle&& fn) = 0;


        // OPTIONAL -- no-op close is default. Will be called when all Channels that refernece it are destructed/
        virtual void close() {};

        // OPTIONAL -- no-op close is default. Will be called right after 
        virtual void async_accept(io_completion_handle&& fn)
        {
            error_code ec;
            fn(ec, 0);
        }

        // OPTIONAL -- no-op close is default. Will be called when all Channels that refernece it are destructed/
        virtual void async_connect(io_completion_handle&& fn)
        {
            error_code ec;
            fn(ec, 0);
        }

    };


    template<typename T>
    class SocketAdapter : public SocketInterface
    {
    public:
        T& mChl;

        SocketAdapter(T& chl)
            :mChl(chl)
        {}

        ~SocketAdapter() override {}

        void async_send(
            span<boost::asio::mutable_buffer> buffers, 
            io_completion_handle&& fn) override
        {

            error_code ec;
            u64 bytesTransfered = 0;
            for (u64 i = 0; i < u64( buffers.size()); ++i) {
                try {
                    // Use boost conversions to get normal pointer size
                    auto data = boost::asio::buffer_cast<u8*>(buffers[i]);
                    auto size = boost::asio::buffer_size(buffers[i]);

                    // NOTE: I am assuming that this is blocking. 
                    // Blocking here cause the networking code to deadlock 
                    // in some senarios. E.g. all threads blocks on recving data
                    // that is not being sent since the threads are blocks. 
                    // Make sure to give the IOService enought threads or make this 
                    // non blocking somehow.
                    mChl.send(data, size);
                    bytesTransfered += size;
                }
                catch (...) {
                    ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
                    break;
                }
            }

            // once all the IO is sent (or error), we should call the callback.
            fn(ec, bytesTransfered);
        }

        void async_recv(
            span<boost::asio::mutable_buffer> buffers, 
            io_completion_handle&& fn) override
        {
            error_code ec;
            u64 bytesTransfered = 0;
            for (u64 i = 0; i < u64(buffers.size()); ++i) {
                try {
                    // Use boost conversions to get normal pointer size
                    auto data = boost::asio::buffer_cast<u8*>(buffers[i]);
                    auto size = boost::asio::buffer_size(buffers[i]);

                    // Note that I am assuming that this is blocking. 
                    // Blocking here cause the networking code to deadlock 
                    // in some senarios. E.g. all threads blocks on recving data
                    // that is not being sent since the threads are blocks. 
                    // Make sure to give the IOService enought threads or make this 
                    // non blocking somehow.
                    mChl.recv(data, size);
                    bytesTransfered += size;
                }
                catch (...) {
                    ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
                    break;
                }
            }
            fn(ec, bytesTransfered);
        }
    };



    class BoostSocketInterface : public SocketInterface
    {
    public:
        boost::asio::ip::tcp::socket mSock;

#ifndef BOOST_ASIO_HAS_MOVE
#error "require move"
#endif

        BoostSocketInterface(boost::asio::ip::tcp::socket&& ios)
            : mSock(std::forward<boost::asio::ip::tcp::socket>(ios))
        {
        }

        ~BoostSocketInterface() override
        {
            close();
        }

        void close() override {
			boost::system::error_code ec;
			mSock.close(ec);
			if (ec) 
                std::cout <<"BoostSocketInterface::close() error: "<< ec.message() << std::endl; 
		}

        void async_recv(span<boost::asio::mutable_buffer> buffers, io_completion_handle&& fn) override
        {
            boost::asio::async_read(mSock, buffers, std::forward<io_completion_handle>(fn));
        }

        void async_send(span<boost::asio::mutable_buffer> buffers, io_completion_handle&& fn) override
        {
            boost::asio::async_write(mSock, buffers, std::forward<io_completion_handle>(fn));
        }
    };
}
