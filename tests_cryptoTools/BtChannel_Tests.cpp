//#include "stdafx.h"
#include <thread>
#include <vector>
#include <memory>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IOService.h>

#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Common/ByteStream.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Finally.h>


#include "BtChannel_Tests.h"

#include "Common.h"


using namespace osuCrypto;

namespace tests_cryptoTools
{
    void BtNetwork_Connect1_Boost_Test()
    {

        setThreadName("Test_Host");

        std::string channelName{ "TestChannel" };
        std::string msg{ "This is the message" };
        ByteStream msgBuff((u8*)msg.data(), msg.size());

        IOService ioService(0);
        auto thrd = std::thread([&]()
        {
            setThreadName("Test_Client");

            //std::cout << "client ep start" << std::endl;
            Endpoint endpoint(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
            //std::cout << "client ep done" << std::endl;

            Channel chl = endpoint.addChannel(channelName, channelName);
            //std::cout << "client chl1 done" << std::endl;


            std::unique_ptr<ByteStream> srvRecv(new ByteStream());

            chl.recv(*srvRecv);


            if (*srvRecv != msgBuff)
            {

                throw UnitTestFail();
            }


            chl.asyncSend(std::move(srvRecv));

            //std::cout << " server closing" << std::endl;

            chl.close();

            //std::cout << " server nm closing" << std::endl;

            //netServer.CloseChannel(chl1.Name());
            endpoint.stop();
            //std::cout << " server closed" << std::endl;

        });

        //IOService ioService;

        //std::cout << "host ep start" << std::endl;

        Endpoint endpoint(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

        //std::cout << "host ep done" << std::endl;

        auto chl = endpoint.addChannel(channelName, channelName);
        //std::cout << "host chl1 done" << std::endl;

        //std::cout << " client channel added" << std::endl;

        chl.asyncSend(msgBuff.begin(), msgBuff.size());

        ByteStream clientRecv;
        chl.recv(clientRecv);

        if (clientRecv != msgBuff)
            throw UnitTestFail();
        //std::cout << " client closing" << std::endl;


        chl.close();
        //netClient.CloseChannel(channelName);
        endpoint.stop();
        //std::cout << " client closed" << std::endl;


        thrd.join();

        ioService.stop();

    }


    void BtNetwork_OneMegabyteSend_Boost_Test()
    {
        //InitDebugPrinting();

        setThreadName("Test_Host");

        std::string channelName{ "TestChannel" };
        std::string msg{ "This is the message" };
        ByteStream oneMegabyte((u8*)msg.data(), msg.size());
        oneMegabyte.reserve(1000000);
        oneMegabyte.setp(1000000);

        memset(oneMegabyte.data() + 100, 0xcc, 1000000 - 100);

        IOService ioService(0);

        auto thrd = std::thread([&]()
        {
            setThreadName("Test_Client");

            Endpoint endpoint(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
            Channel chl = endpoint.addChannel(channelName, channelName);

            std::unique_ptr<ByteStream> srvRecv(new ByteStream());
            chl.recv(*srvRecv);

            if ((*srvRecv) != oneMegabyte)
                throw UnitTestFail();

            chl.asyncSend(std::move(srvRecv));

            chl.close();

            endpoint.stop();

        });


        Endpoint endpoint(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");
        auto chl = endpoint.addChannel(channelName, channelName);

        chl.asyncSend(oneMegabyte.begin(), oneMegabyte.size());

        ByteStream clientRecv;
        chl.recv(clientRecv);

        if (clientRecv != oneMegabyte)
            throw UnitTestFail();

        chl.close();
        endpoint.stop();
        thrd.join();

        ioService.stop();
    }


    void BtNetwork_ConnectMany_Boost_Test()
    {
        //InitDebugPrinting();
        setThreadName("Test_Host");

        std::string channelName{ "TestChannel" };

        u64 numChannels(15);
        u64 messageCount(15);

        bool print(false);

        ByteStream buff(64);
        buff.setp(64);

        buff.data()[14] = 3;
        buff.data()[24] = 6;
        buff.data()[34] = 8;
        buff.data()[44] = 2;

        std::thread serverThrd = std::thread([&]()
        {
            IOService ioService;
            setThreadName("Test_client");

            Endpoint endpoint(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");

            std::vector<std::thread> threads;

            for (u64 i = 0; i < numChannels; i++)
            {
                threads.emplace_back([i, &buff, &endpoint, messageCount, print, channelName]()
                {
                    setThreadName("Test_client_" + std::to_string(i));
                    auto chl = endpoint.addChannel(channelName + std::to_string(i), channelName + std::to_string(i));
                    ByteStream mH;

                    for (u64 j = 0; j < messageCount; j++)
                    {
                        chl.recv(mH);
                        if (buff != mH)throw UnitTestFail();
                        chl.asyncSend(buff.begin(), buff.size());
                    }

                    chl.close();

                    //std::stringstream ss;
                    //ss << "server" << i << " done\n";
                    //std::cout << ss.str();
                });
            }


            for (auto& thread : threads)
                thread.join();


            endpoint.stop();
            ioService.stop();
            //std::cout << "server done" << std::endl;
        });

        IOService ioService;

        Endpoint endpoint(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

        std::vector<std::thread> threads;

        for (u64 i = 0; i < numChannels; i++)
        {
            threads.emplace_back([i, &endpoint, &buff, messageCount, print, channelName]()
            {
                setThreadName("Test_Host_" + std::to_string(i));
                auto chl = endpoint.addChannel(channelName + std::to_string(i), channelName + std::to_string(i));
                ByteStream mH(buff);

                for (u64 j = 0; j < messageCount; j++)
                {
                    chl.asyncSendCopy(mH);
                    chl.recv(mH);

                    if (buff != mH)throw UnitTestFail();
                }


                chl.close();
            });
        }



        for (auto& thread : threads)
            thread.join();

        endpoint.stop();

        serverThrd.join();

        ioService.stop();

    }


    void BtNetwork_CrossConnect_Test()
    {
        const block send = _mm_set_epi64x(123412156, 123546);
        const block recv = _mm_set_epi64x(7654333, 8765433);

        auto thrd = std::thread([&]() {
            IOService ioService(0);
            //setThreadName("Net_Cross1_Thread");
            Endpoint endpoint(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");


            auto sendChl1 = endpoint.addChannel("send", "recv");
            auto recvChl1 = endpoint.addChannel("recv", "send");

            ByteStream buff;
            buff.append(send);

            sendChl1.asyncSendCopy(buff);
            block temp;

            recvChl1.recv(buff);
            buff.consume((u8*)&temp, 16);

            if (neq(temp, send))
                throw UnitTestFail();

            buff.setp(0);
            buff.append(recv);
            recvChl1.asyncSendCopy(buff);

            sendChl1.recv(buff);

            buff.consume((u8*)&temp, 16);

            if (neq(temp, recv))
                throw UnitTestFail();

            recvChl1.close();
            sendChl1.close();

            endpoint.stop();

            ioService.stop();
        });
        IOService ioService(0);
        Endpoint endpoint(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");


        auto recvChl0 = endpoint.addChannel("recv", "send");
        auto sendChl0 = endpoint.addChannel("send", "recv");

        ByteStream buff;
        buff.append(send);

        sendChl0.asyncSendCopy(buff);
        block temp;

        recvChl0.recv(buff);
        buff.consume((u8*)&temp, 16);

        if (neq(temp, send))
            throw UnitTestFail();

        buff.setp(0);
        buff.append(recv);
        recvChl0.asyncSendCopy(buff);

        sendChl0.recv(buff);

        buff.consume((u8*)&temp, 16);

        if (neq(temp, recv))
            throw UnitTestFail();

        sendChl0.close();
        recvChl0.close();

        thrd.join();
        endpoint.stop();
        ioService.stop();

    }


    void BtNetwork_ManyEndpoints_Test()
    {
        u64 nodeCount = 10;
        u32 basePort = 1212;
        std::string ip("127.0.0.1");
        //InitDebugPrinting();

        std::vector<std::thread> nodeThreads(nodeCount);

        setThreadName("main");

        for (u64 i = 0; i < nodeCount; ++i)
        {
            nodeThreads[i] = std::thread([&, i]() {

                setThreadName("node" + std::to_string(i));


                u32 port;// = basePort + i;
                IOService ioService(0);
                ioService.printErrorMessages(true);

                std::list<Endpoint> endpoints;
                std::vector<Channel> channels;

                for (u64 j = 0; j < nodeCount; ++j)
                {
                    if (j != i)
                    {
                        EpMode host = i > j ? EpMode::Server : EpMode::Client;
                        std::string name("endpoint:");
                        if (host == EpMode::Server)
                        {
                            name += std::to_string(i) + "->" + std::to_string(j);
                            port = basePort + (u32)i;
                        }
                        else
                        {
                            name += std::to_string(j) + "->" + std::to_string(i);
                            port = basePort + (u32)j;
                        }

                        endpoints.emplace_back(ioService, ip, port, host, name);

                        channels.push_back(endpoints.back().addChannel("chl", "chl"));
                    }
                }
                for (u64 j = 0, idx = 0; idx < nodeCount; ++j, ++idx)
                {
                    if (j == i)
                    {
                        ++idx;
                        if (idx == nodeCount)
                            break;
                    }

                    std::string msg = "hello" + std::to_string(idx);
                    channels[j].asyncSend(std::move(std::unique_ptr<ByteStream>(new ByteStream((u8*)msg.data(), msg.size()))));
                }

                std::string expected = "hello" + std::to_string(i);

                for (auto& chl : channels)
                {
                    ByteStream recv;
                    chl.recv(recv);
                    std::string msg((char*)recv.data(), recv.size());


                    if (msg != expected)
                        throw UnitTestFail();
                }
                //std::cout << IoStream::lock << "re " << i << std::endl << IoStream::unlock;

                for (auto& chl : channels)
                    chl.close();

                for (auto& endpoint : endpoints)
                    endpoint.stop();


                ioService.stop();
            });
        }

        for (u64 i = 0; i < nodeCount; ++i)
            nodeThreads[i].join();
    }

    void BtNetwork_AsyncConnect_Boost_Test()
    {
        setThreadName("Test_Host");


        std::string channelName{ "TestChannel" };
        std::string msg{ "This is the message" };

        IOService ioService(4);

        Endpoint ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
        auto chl1 = ep1.addChannel(channelName, channelName);
        Finally cleanup1([&]() { chl1.close(); ep1.stop(); ioService.stop(); });

        if (chl1.isConnected() == true) throw UnitTestFail();


        Endpoint ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");
        Finally cleanup2([&]() { ep2.stop(); });

        if (chl1.isConnected() == true) throw UnitTestFail();


        auto chl2 = ep2.addChannel(channelName, channelName);
        Finally cleanup3([&]() { chl2.close(); });

        chl1.waitForConnection();

        if (chl1.isConnected() == false) throw UnitTestFail();
    }

    void BtNetwork_std_Containers_Test()
    {
        setThreadName("Test_Host");
        std::string channelName{ "TestChannel" }, msg{ "This is the message" };
        IOService ioService;

        Endpoint ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
        Endpoint ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

        auto chl1 = ep1.addChannel(channelName, channelName);
        auto chl2 = ep2.addChannel(channelName, channelName);

        Finally cleanup([&]() {
            chl1.close();
            chl2.close();
            ep1.stop();
            ep2.stop();
            ioService.stop();
        });


        std::vector<u32> vec_u32{ 0,1,2,3,4,5,6,7,8,9 };
        std::array<u32, 10> arr_u32_10;
        chl1.send(vec_u32);
        chl2.recv(arr_u32_10);

        if (std::mismatch(vec_u32.begin(), vec_u32.end(), arr_u32_10.begin()).first != vec_u32.end())
            throw UnitTestFail("send vec, recv array");




        chl2.asyncSend(std::move(vec_u32));
        chl1.recv(vec_u32);

        if (std::mismatch(vec_u32.begin(), vec_u32.end(), arr_u32_10.begin()).first != vec_u32.end())
            throw UnitTestFail("send vec, recv array");



        std::string hello{ "hello world" };
        chl2.asyncSend(std::move(hello));
        chl1.recv(hello);

        if (hello != "hello world") UnitTestFail("std::string move");


    }


    void BtNetwork_bitVector_Test()
    {
        setThreadName("Test_Host");
        std::string channelName{ "TestChannel" }, msg{ "This is the message" };
        IOService ioService;

        Endpoint ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
        Endpoint ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

        auto chl1 = ep1.addChannel(channelName, channelName);
        auto chl2 = ep2.addChannel(channelName, channelName);


        BitVector bb(77);
        bb[55] = 1;
        bb[33] = 1;

        chl1.send(bb);
        chl2.recv(bb);


        if (!bb[55] || !bb[33])
            throw UnitTestFail();


    }



    void BtNetwork_recvErrorHandler_Test()
    {


        setThreadName("Test_Host");
        std::string channelName{ "TestChannel" }, msg{ "This is the message" };
        IOService ioService;

        ioService.printErrorMessages(false);

        Endpoint ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
        Endpoint ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

        auto chl1 = ep1.addChannel(channelName, channelName);
        auto chl2 = ep2.addChannel(channelName, channelName);

        Finally cleanup([&]() {
            chl1.close();
            chl2.close();
            ep1.stop();
            ep2.stop();
            ioService.stop();
        });


        std::vector<u32> vec_u32{ 0,1,2,3,4,5,6,7,8,9 };
        std::array<u32, 3> arr_u32_3;

        chl1.send(vec_u32);

        bool throws = true;
        try
        {

            chl2.recv(arr_u32_3);
            throws = false;
        }
        catch (BadReceiveBufferSize e)
        {
            if (e.mSize != vec_u32.size() * sizeof(u32))
                throw UnitTestFail();

            std::vector<u32> backup(vec_u32.size());

            e.mRescheduler((u8*)backup.data());

            if (std::mismatch(vec_u32.begin(), vec_u32.end(), backup.begin()).first != vec_u32.end())
                throw UnitTestFail("send vec, recv backup");
        }

        if (throws == false)
            throw UnitTestFail("No throw on back recv size");


        std::array<u32, 10> arr_u32_10;
        chl1.send(vec_u32);
        chl2.recv(arr_u32_10);

        if (std::mismatch(vec_u32.begin(), vec_u32.end(), arr_u32_10.begin()).first != vec_u32.end())
            throw UnitTestFail("failed to recover bad recv size.");
    }

    void BtNetwork_closeOnError_Test()
    {

        bool throws = false;
        try {

            setThreadName("Test_Host");
            std::string channelName{ "TestChannel" }, msg{ "This is the message" };
            IOService ioService;

            ioService.printErrorMessages(false);

            Endpoint ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
            Endpoint ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

            auto chl1 = ep1.addChannel(channelName, channelName);

            Finally cleanup([&]() {
                chl1.close();
                ep1.stop();
                ep2.stop();
                ioService.stop();
            });


            {
                auto chl2 = ep2.addChannel(channelName, channelName);
                chl2.close();
            }

            std::vector<u32> vec_u32{ 0,1,2,3,4,5,6,7,8,9 };
            chl1.recv(vec_u32);

        }
        catch (NetworkError e)
        {
            throws = true;
        }


        if (throws == false)
        {
            throw UnitTestFail("no throw");
        }

        throws = false;

        try {

            setThreadName("Test_Host");
            std::string channelName{ "TestChannel" }, msg{ "This is the message" };
            IOService ioService;
            ioService.printErrorMessages(false);

            Endpoint ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
            Endpoint ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

            auto chl1 = ep1.addChannel(channelName, channelName);
            auto chl2 = ep2.addChannel(channelName, channelName);

            //Finally cleanup([&]() {
            //    chl2.close();
            //    ep1.stop();
            //    ep2.stop();
            //    ioService.stop();
            //});


            std::vector<u32> vec_u32{ 0,1,2,3,4,5,6,7,8,9 };
            chl1.send(vec_u32);
            chl1.close();


            chl2.recv(vec_u32);
            chl2.recv(vec_u32);

        }
        catch (NetworkError e)
        {
            throws = true;
        }


        if (throws == false)
        {
            throw UnitTestFail("no throw");
        }


    }

    void BtNetwork_SocketInterface_Test()
    {

        try {
            //auto i = new std::future<int>();
            //{
            //    std::promise<int> p;
            //}
            //{
            //    std::promise<int> p;
            //    p.set_value(1);
            //}

            //{
            //    std::promise<int> p;
            //    *i = p.get_future();
            //    //p.set_value(1);
            //}
            //i->get();
            //delete i;
            //return;

            std::string channelName{ "TestChannel" }, msg{ "This is the message" };
            IOService ioService;

            ioService.printErrorMessages(false);

            Endpoint ep1(ioService, "127.0.0.1", 1212, EpMode::Client, "endpoint");
            Endpoint ep2(ioService, "127.0.0.1", 1212, EpMode::Server, "endpoint");

            auto chl1 = ep1.addChannel(channelName, channelName);
            auto chl2 = ep2.addChannel(channelName, channelName);

            //////////////////////////////////////////////////////////////////////////
            //////////////////////////////////////////////////////////////////////////


            Channel ichl1(ioService, new SocketAdapter<Channel>(chl1));
            Channel ichl2(ioService, new SocketAdapter<Channel>(chl2));


            ichl1.asyncSendCopy(msg);

            std::string msg2;
            ichl2.recv(msg2);

            if (msg != msg2)
            {
                throw UnitTestFail(LOCATION);
            }
        }
        catch (std::exception e)
        {
            std::cout <<"sss" << e.what() << std::endl;
        }
    }
}