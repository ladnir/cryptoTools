#pragma once
#include <cryptoTools/Common/config.h>
#ifdef ENABLE_BOOST

#include <boost/asio.hpp>
#include <cryptoTools/Common/Defines.h>
#include "IoBuffer.h"
#include <iostream>
#include "util.h"

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

        virtual void cancel() {
            std::cout << "Please override SocketInterface::cancel() if you"<<
            " want to properly support cancel operations. Calling std::terminate() " << LOCATION << std::endl;
            std::terminate();
        };

        // OPTIONAL -- no-op close is default. Will be called right after 
        virtual void async_accept(completion_handle&& fn)
        {
            error_code ec;
            fn(ec);
        }

        // OPTIONAL -- no-op close is default. Will be called when all Channels that refernece it are destructed/
        virtual void async_connect(completion_handle&& fn)
        {
            error_code ec;
            fn(ec);
        }

        // a function that gives this socket access to the IOService.
        // This is called right after being handed to the Channel.
        virtual void setIOService(IOService& ios) { }
    };


    template<typename T>
    class SocketAdapter : public SocketInterface
    {
    public:
        T& mChl;
        IOService* mIos = nullptr;

        SocketAdapter(T& chl)
            :mChl(chl)
        {}

        ~SocketAdapter() override {}

        void setIOService(IOService& ios) override { mIos = &ios; }

        void async_send(
            span<boost::asio::mutable_buffer> buffers, 
            io_completion_handle&& fn) override
        {
            mIos->mIoService.post([this, buffers, fn]() {
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
            });
        }

        void async_recv(
            span<boost::asio::mutable_buffer> buffers, 
            io_completion_handle&& fn) override
        {
            mIos->mIoService.post([this, buffers, fn]() {
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
            });
        }

        void cancel() override
        {
            mChl.asyncCancel([](){});
        }
    };


    class FifoSocket : public SocketInterface {
    public:
        FifoSocket() = delete;
        FifoSocket(const FifoSocket&) = delete;
        FifoSocket(FifoSocket&&) = delete;

#ifdef BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR
        typedef boost::asio::posix::stream_descriptor stream_descriptor;
#else // BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR
        typedef boost::asio::windows::stream_handle stream_descriptor;
#endif // BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR


        stream_descriptor mHandle;

        static void removeFifo(std::string name)
        {
            std::remove(name.c_str());
        }

        static void createFifo(std::string name)
        {
#ifdef BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR
            auto ret = mkfifo(name.c_str(), 0666);
            if (ret)
            {
                switch (errno)
                {

                case EACCES:
                    throw std::runtime_error("FifoSocket : One of the directories in pathname did not allow search(execute) permission.");
                case EDQUOT:
                    throw std::runtime_error("FifoSocket : The user's quota of disk blocks or inodes on the file system has been exhausted. ");
                case EEXIST:
                    throw std::runtime_error("FifoSocket : pathname already exists.This includes the case where pathname is a symbolic link, dangling or not.");
                case ENAMETOOLONG:
                    throw std::runtime_error("FifoSocket : Either the total length of pathname is greater than PATH_MAX, or an individual filename component has a length greater than NAME_MAX.In the GNU system, there is no imposed limit on overall filename length, but some file systems may place limits on the length of a component.");
                case ENOENT:
                    throw std::runtime_error("FifoSocket : A directory component in pathname does not exist or is a dangling symbolic link.");
                case ENOSPC:
                    throw std::runtime_error("FifoSocket : The directory or file system has no room for the new file.");
                case ENOTDIR:
                    throw std::runtime_error("FifoSocket : A component used as a directory in pathname is not, in fact, a directory.");
                case EROFS:
                    throw std::runtime_error("FifoSocket : pathname refers to a read - only file system.");
                default:
                    throw std::runtime_error("FifoSocket : mkfifo failed with errno:" + std::to_string(errno));
                }
            }
#else
            throw std::runtime_error("Fifo on windows is not implemented");
#endif
        }


        FifoSocket(boost::asio::io_context& ios, std::string name, SessionMode mode)
            :mHandle(ios)
        {
#ifdef BOOST_ASIO_HAS_POSIX_STREAM_DESCRIPTOR
            auto fd = open(name.c_str(), O_RDWR);

            if (fd == -1)
                throw std::runtime_error("failed to open file: " + name);

            mHandle.assign(fd);
#else
            throw std::runtime_error("Fifo on windows is not implemented");
            //auto iter = std::find(name.begin(), name.end(), '\\');
            //if (iter != name.end())
            //    throw std::runtime_error("on windows name can not caintain backslash.");
            //name = "\\\\.\\pipe\\" + name;

            //stream_descriptor::native_handle_type fd;
            //if (mode == SessionMode::Server)
            //{
            //    fd = CreateNamedPipe(
            //        name.c_str(), 
            //        PIPE_ACCESS_DUPLEX, 
            //        PIPE_TYPE_BYTE | PIPE_NOWAIT, 
            //        1, 
            //        1 << 20, 
            //        1 << 20, 
            //        1000, 
            //        nullptr);

            //    auto success = ConnectNamedPipe(fd, nullptr);

            //    if (success == false)
            //        throw std::runtime_error("failed to connect to named pipe.");
            //}
            //else
            //{
            //    auto success = CallNamedPipe(name.c_str(), inBuffSize, outBuffSize, )
            //}
#endif
        }


        // This party has requested some data. Write the data
        // if we currently have it. Otherwise we will store the
        // request and fulfill is when the data arrives.
        void async_recv(
            span<boost::asio::mutable_buffer> buffers,
            io_completion_handle&& fn) override
        {
            boost::asio::async_read(
                mHandle,
                buffers,
                std::forward<io_completion_handle>(fn));
        }

        // This party has requested us to send some data.
        // We will write this data to the buffer and then
        // check to see if the other party has an outstanding
        // recv request. If so we will try and fulfill it.
        // Finally we call our own callback saying that the
        // data has been sent.
        void async_send(
            span<boost::asio::mutable_buffer> buffers,
            io_completion_handle&& fn) override
        {
            boost::asio::async_write(
                mHandle,
                buffers,
                std::forward<io_completion_handle>(fn));
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

        void cancel() override
        {
			boost::system::error_code ec;
#if defined(BOOST_ASIO_MSVC) && (BOOST_ASIO_MSVC >= 1400) \
  && (!defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600) \
  && !defined(BOOST_ASIO_ENABLE_CANCELIO)
            mSock.close(ec);
#else
			mSock.cancel(ec);
#endif

			if (ec) 
                std::cout <<"BoostSocketInterface::cancel() error: "<< ec.message() << std::endl; 
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
#endif