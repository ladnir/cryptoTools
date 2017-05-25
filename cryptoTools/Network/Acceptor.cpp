#include <cryptoTools/Network/Acceptor.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/ByteStream.h>

#include <boost/lexical_cast.hpp>

namespace osuCrypto {


    Acceptor::Acceptor(IOService& ioService)
        :
        mStoppedListeningFuture(mStoppedListeningPromise.get_future()),
        mSocketChannelPairsRemovedFuture(mSocketChannelPairsRemovedProm.get_future()),
        mIOService(ioService),
        mHandle(ioService.mIoService),
        mStopped(false),
        mPort(0)
    {
        mStopped = false;


    }



    Acceptor::~Acceptor()
    {
        stop();


    }




    void Acceptor::bind(u32 port, std::string ip)
    {
        auto pStr = std::to_string(port);
        mPort = port;

        boost::asio::ip::tcp::resolver resolver(mIOService.mIoService);
        boost::asio::ip::tcp::resolver::query
            query(ip, pStr);

        mAddress = *resolver.resolve(query);

        mHandle.open(mAddress.protocol());
        mHandle.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        boost::system::error_code ec;
        mHandle.bind(mAddress, ec);

        if (mAddress.port() != port)
            throw std::runtime_error("rt error at " LOCATION);

        if (ec)
        {
            std::cout << ec.message() << std::endl;

            throw std::runtime_error(ec.message());
        }


        mHandle.listen(boost::asio::socket_base::max_connections);
    }

    void Acceptor::start()
    {
        if (stopped() == false)
        {


            BoostSocketInterface* newSocket = new BoostSocketInterface(mIOService.mIoService);
            mHandle.async_accept(newSocket->mSock, [newSocket, this](const boost::system::error_code& ec)
            {
                start();

                if (!ec)
                {
                    //std::cout << "async_accept new connection" << std::endl;

                    auto buff = new ByteStream(4);
                    buff->setp(buff->capacity());

                    boost::asio::ip::tcp::no_delay option(true);
                    newSocket->mSock.set_option(option);

                    //boost::asio::socket_base::receive_buffer_size option2(262144);
                    //newSocket->mHandle.set_option(option2);
                    //newSocket->mHandle.get_option(option2);
                    //std::cout << option2.value() << std::endl;


                    //boost::asio::socket_base::send_buffer_size option3((1 << 20 )/8);
                    //newSocket->mHandle.set_option(option3);
                    //newSocket->mHandle.get_option(option3);
                    //std::cout << option3.value() << std::endl;

                    newSocket->mSock.async_receive(boost::asio::buffer(buff->data(), buff->size()),
                        [newSocket, buff, this](const boost::system::error_code& ec2, u64 bytesTransferred)
                    {
                        if (!ec2 && bytesTransferred == 4)
                        {

                            //std::cout << "async_accept new connection size" << std::endl;

                            u32 size = buff->getspan<u32>()[0];

                            buff->reserve(size);
                            buff->setp(size);

                            newSocket->mSock.async_receive(boost::asio::buffer(buff->data(), buff->size()),
                                [newSocket, buff, size, this](const boost::system::error_code& ec3, u64 bytesTransferred2)
                            {
                                if (!ec3 && bytesTransferred2 == size)
                                {
                                    // lets split it into pieces.
                                    auto str = std::string((char*)buff->data(), buff->size());

                                    //std::cout << IoStream::lock << "async_accept new connection name: "<<str << std::endl << IoStream::unlock;


                                    auto names = split(str, '`');

                                    if (str.back() == '`' && names.size() == 2) names.emplace_back("");

                                    // Now lets create or get the std::promise<WinNetSocket> that will hold this socket
                                    // for the WinNetEndpoint that will eventually receive it.
                                    //getSocketPromise(names[0], names[2], names[1]);
                                    asyncSetSocket(names[0], names[2], names[1], newSocket);
                                    //prom->first
                                    //prom.set_value(newSocket);
                                }
                                else
                                {

                                    std::cout << "async_accept error, failed to receive first header on connection handshake."
                                        << " Other party may have closed the connection. "
                                        << ((ec3 != 0) ? "Error code:" + ec3.message() : " received " + ToString(bytesTransferred2) + " / 4 bytes") << "  " << LOCATION << std::endl;

                                    delete newSocket;
                                }

                                delete buff;
                            });

                        }
                        else
                        {
                            std::cout << "async_accept error, failed to receive first header on connection handshake."
                                << " Other party may have closed the connection. "
                                << ((ec2 != 0) ? "Error code:" + ec2.message() : " received " + ToString(bytesTransferred) + " / 4 bytes") << "  " << LOCATION << std::endl;

                            delete newSocket;
                            delete buff;
                        }

                    });
                }
                else
                {
                    //std::cout << IoStream::lock<< "async_accept failed with error_code:" << ec.message() << std::endl << IoStream::unlock;
                    delete newSocket;
                }
            });
        }
        else
        {
            mStoppedListeningPromise.set_value();
        }
    }

    void Acceptor::stop()
    {
        //std::cout << "\n#################################### acceptor stop ################################" << std::endl;

        if (mStopped == false)
        {

            {
                mSocketChannelPairsMtx.lock();
                mStopped = true;

                if (mSocketChannelPairs.size() == 0)
                    mSocketChannelPairsRemovedProm.set_value();

                mSocketChannelPairsMtx.unlock();
            }

            mSocketChannelPairsRemovedFuture.get();

            mHandle.close();

            mStoppedListeningFuture.get();
        }

    }

    bool Acceptor::stopped() const
    {
        return mStopped;
    }

    void Acceptor::asyncGetSocket(ChannelBase & chl)
    {
        std::string tag = chl.mEndpoint->getName() + ":" + chl.mLocalName+ ":" + chl.mRemoteName;

        {
            //std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);
            mSocketChannelPairsMtx.lock();
             
            auto iter = mSocketChannelPairs.find(tag);

            if (iter == mSocketChannelPairs.end())
            {

                //std::cout << IoStream::lock << "asyncGetSocket waiting on socket " << tag << std::endl << IoStream::unlock;
                mSocketChannelPairs.emplace(tag, std::pair<BoostSocketInterface*, ChannelBase*>(nullptr, &chl));
            }
            else
            {
               // std::cout <<IoStream::lock << "asyncGetSocket aquired socket " << tag << std::endl << IoStream::unlock;
                if (iter->second.first == nullptr)
                {
                    std::cout << "netowrking error: channel " << tag << " already exists.";
                    std::terminate();
                }

                chl.mHandle.reset(iter->second.first);

                chl.mRecvSocketSet = true;
                chl.mSendSocketSet = true;
                chl.mOpenProm.set_value();

                //std::cout << "erase1   " << iter->first << std::endl;
                mSocketChannelPairs.erase(iter);


                if (mStopped == true && mSocketChannelPairs.size() == 0)
                {
                    mSocketChannelPairsRemovedProm.set_value();
                }
            }
            mSocketChannelPairsMtx.unlock();
        }
    }

    void Acceptor::remove(
        std::string endpointName,
        std::string localChannelName,
        std::string remoteChannelName)
    {
        std::string tag = endpointName + ":" + localChannelName + ":" + remoteChannelName;

        {
            mSocketChannelPairsMtx.lock();
            //std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);
            auto iter = mSocketChannelPairs.find(tag);

            if (iter != mSocketChannelPairs.end())
            {

                if (iter->second.first)
                {
                    iter->second.first->close();
                    delete iter->second.first;

                    //std::cout << "erase2   " << iter->first << std::endl;
                    mSocketChannelPairs.erase(iter);


                    if (mStopped == true && mSocketChannelPairs.size() == 0)
                    {
                        mSocketChannelPairsRemovedProm.set_value();
                    }
                }
                else
                {
                    iter->second.second = nullptr;
                }
            }
            mSocketChannelPairsMtx.unlock();
        }
    }


    void Acceptor::asyncSetSocket(
        std::string endpointName,
        std::string localChannelName,
        std::string remoteChannelName,
        BoostSocketInterface* sock)
    {
        std::string tag = endpointName + ":" + localChannelName + ":" + remoteChannelName;

        {
            //std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);
            mSocketChannelPairsMtx.lock();

            const auto iter = mSocketChannelPairs.find(tag);

            if (iter == mSocketChannelPairs.end())
            {
                //std::cout << "asyncSetSocket created socket " << tag << std::endl;
                mSocketChannelPairs.emplace(tag, std::pair<BoostSocketInterface*, ChannelBase*>(sock, nullptr));
            }
            else
            {

                if (iter->second.second == nullptr)
                {
                    boost::system::error_code ec;
                    sock->mSock.close(ec);


                    if (ec)
                    {
                        std::cout << ec.message() << std::endl;
                    }
                }
                else
                {
                    iter->second.second->mHandle.reset(sock);

                    mIOService.startSocket(iter->second.second);
                }

                mSocketChannelPairs.erase(iter);


                if (mStopped == true && mSocketChannelPairs.size() == 0)
                {
                    mSocketChannelPairsRemovedProm.set_value();
                }
            }
            mSocketChannelPairsMtx.unlock();
        }

    }
}
