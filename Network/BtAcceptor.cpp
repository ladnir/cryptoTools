#include "cryptoTools/Network/BtAcceptor.h"
#include "cryptoTools/Network/BtIOService.h"
#include "cryptoTools/Network/BtChannel.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ByteStream.h"

#include "boost/lexical_cast.hpp"

namespace osuCrypto {


    BtAcceptor::BtAcceptor(BtIOService& ioService)
        :
        mStoppedFuture(mStoppedPromise.get_future()),
        mIOService(ioService),
        mHandle(ioService.mIoService),
        mStopped(false),
        mPort(0)
    {
        mStopped = false;


    }



    BtAcceptor::~BtAcceptor()
    {
        stop();


        mStoppedFuture.get();
    }




    void BtAcceptor::bind(u32 port, std::string ip)
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

        if(ec)
        {
            std::cout << ec.message() << std::endl;

            throw std::runtime_error(ec.message());
        }


        mHandle.listen(boost::asio::socket_base::max_connections);
    }

    void BtAcceptor::start() 
    {
        if (stopped() == false)
        {


            boost::asio::ip::tcp::socket* newSocket = new boost::asio::ip::tcp::socket(mIOService.mIoService);
            mHandle.async_accept(*newSocket, [newSocket, this](const boost::system::error_code& ec)
            {
                start();

                if (!ec)
                {

                    auto buff = new ByteStream(4);
                    buff->setp(buff->capacity());

                    boost::asio::ip::tcp::no_delay option(true);
                    newSocket->set_option(option);

                    //boost::asio::socket_base::receive_buffer_size option2(262144);
                    //newSocket->mHandle.set_option(option2);
                    //newSocket->mHandle.get_option(option2);
                    //std::cout << option2.value() << std::endl;


                    //boost::asio::socket_base::send_buffer_size option3((1 << 20 )/8);
                    //newSocket->mHandle.set_option(option3);
                    //newSocket->mHandle.get_option(option3);
                    //std::cout << option3.value() << std::endl;

                    newSocket->async_receive(boost::asio::buffer(buff->data(), buff->size()), 
                        [newSocket, buff, this](const boost::system::error_code& ec2, u64 bytesTransferred)
                    {
                        if(!ec2 || bytesTransferred != 4)
                        {
                            u32 size = buff->getArrayView<u32>()[0];

                            buff->reserve(size);
                            buff->setp(size);

                            newSocket->async_receive(boost::asio::buffer(buff->data(), buff->size()),
                                [newSocket, buff, size, this](const boost::system::error_code& ec3, u64 bytesTransferred2)
                            {
                                if (!ec3 || bytesTransferred2 != size)
                                {
                                    // lets split it into pieces.
                                    auto str = std::string((char*)buff->data(), buff->size());
                                    auto names = split(str, '`');

                                    if (str.back() == '`' && names.size() == 2) names.emplace_back("");

                                    // Now lets create or get the std::promise<WinNetSocket> that will hold this socket
                                    // for the WinNetEndpoint that will eventually receive it.
                                    //getSocketPromise(names[0], names[2], names[1]);
                                    asyncSetHandel(names[0], names[2], names[1], newSocket);
                                    //prom->first
                                    //prom.set_value(newSocket);
                                }
                                else
                                {
                                    std::cout << "async_accept->async_receive->async_receive (body) failed with error_code:" << ec3.message() << std::endl;
                                }

                                delete buff;
                            });

                        }
                        else
                        {
                            std::cout << "async_accept->async_receive (header) failed with error_code:" << ec2.message() << std::endl;
                            delete newSocket;
                            delete buff;
                        }

                    });
                }
                else
                {
                    //std::cout << "async_accept failed with error_code:" << ec.message() << std::endl;
                    delete newSocket;
                }
            });
        }
        else
        {
            mStoppedPromise.set_value();
        }
    }

    void BtAcceptor::stop()
    {
        mStopped = true;
        mHandle.close();
    }

    bool BtAcceptor::stopped() const
    {
        return mStopped;
    }

    void BtAcceptor::asyncGetHandel(BtChannel & chl)
    {
        std::string tag = chl.getEndpoint().getName() + ":" + chl.getName() + ":" + chl.getRemoteName();

        {
            std::unique_lock<std::mutex> lock(mMtx);
            auto iter = mSocketPromises.find(tag);

            if (iter == mSocketPromises.end())
            {
                mSocketPromises.emplace(tag, std::pair<boost::asio::ip::tcp::socket*, BtChannel*>(nullptr, &chl));
            }
            else
            { 
                chl.mHandle = iter->second.first;
                chl.mRecvSocketSet = true;
                chl.mSendSocketSet = true;
                chl.mOpenProm.set_value();
            }
        }
        //return std::move(mSocketPromises[tag].get_future().get());
    }

    void BtAcceptor::asyncSetHandel(
        std::string endpointName,
        std::string localChannelName,
        std::string remoteChannelName, 
        boost::asio::ip::tcp::socket* sock)
    {
        std::string tag = endpointName + ":" + localChannelName + ":" + remoteChannelName;

        {
            std::unique_lock<std::mutex> lock(mMtx);
            auto iter = mSocketPromises.find(tag);

            if (iter == mSocketPromises.end())
            {
                mSocketPromises.emplace(tag, std::pair<boost::asio::ip::tcp::socket*, BtChannel*>(sock, nullptr));
            }
            else
            {
                if (iter->second.second->mHandle)
                    throw std::runtime_error(LOCATION);

                iter->second.second->mHandle = sock;

                mIOService.startSocket(iter->second.second);
            }
        }

    }
}
