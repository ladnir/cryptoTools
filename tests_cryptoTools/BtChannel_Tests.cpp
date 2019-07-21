//#include "stdafx.h"
#include <thread>
#include <vector>
#include <memory>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IOService.h>

#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Finally.h>


#include "BtChannel_Tests.h"

#include "Common.h"
#include <cryptoTools/Common/TestCollection.h>
#include <chrono>
#include <thread>
using namespace osuCrypto;

namespace tests_cryptoTools
{

    void BtNetwork_AnonymousMode_Test()
    {
        IOService ioService(0);
        Session s1(ioService, "127.0.0.1", 1212, SessionMode::Server);
        Session s2(ioService, "127.0.0.1", 1212, SessionMode::Server);

        Session c1(ioService, "127.0.0.1", 1212, SessionMode::Client);
        Session c2(ioService, "127.0.0.1", 1212, SessionMode::Client);

        auto c1c1 = c1.addChannel();
        auto c1c2 = c1.addChannel();
        auto s1c1 = s1.addChannel();
        auto s1c2 = s1.addChannel();
        auto c2c1 = c2.addChannel();
        auto c2c2 = c2.addChannel();
        auto s2c1 = s2.addChannel();
        auto s2c2 = s2.addChannel();

        std::string m1 = "m1";
        std::string m2 = "m2";


        c1c1.send(m1);
        c2c1.send(m1);
        c1c2.send(m2);
        c2c2.send(m2);

        std::string t;

        s1c1.recv(t);
        if (m1 != t) throw UnitTestFail();

        s2c1.recv(t);
        if (m1 != t) throw UnitTestFail();

        s1c2.recv(t);
        if (m2 != t) throw UnitTestFail();

        s2c2.recv(t);
        if (m2 != t) throw UnitTestFail();


        if (c1c1.getName() != s1c1.getName()) throw UnitTestFail();
        if (c2c1.getName() != s2c1.getName()) throw UnitTestFail();
        if (c1c2.getName() != s1c2.getName()) throw UnitTestFail();
        if (c2c2.getName() != s2c2.getName()) throw UnitTestFail();

        if (s1.getSessionID() != c1.getSessionID()) throw UnitTestFail();
        if (s2.getSessionID() != c2.getSessionID()) throw UnitTestFail();

    }

    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_CancelChannel_Test);
    void BtNetwork_CancelChannel_Test()
    {
        u64 trials = 10;
        IOService ioService;
        ioService.showErrorMessages(false);
        //Timer& t = gTimer;

        for (u64 i = 0; i < trials; ++i)
        {

            {
                Session c1(ioService, "127.0.0.1", 1212, SessionMode::Client);

                auto ch1 = c1.addChannel();

                ch1.cancel();

                bool throws = false;

                try { ch1.waitForConnection(); }
                catch (...) { throws = true; }

                if (throws == false)
                    throw UnitTestFail();

                if (ch1.isConnected())
                    throw UnitTestFail();
            }

            {
                Session c1(ioService, "127.0.0.1", 1212, SessionMode::Server);
                auto ch1 = c1.addChannel();

                ch1.cancel();

                bool throws = false;

                try { ch1.waitForConnection(); }
                catch (...) { throws = true; }

                if (throws == false)
                    throw UnitTestFail();

                if (ch1.isConnected())
                    throw UnitTestFail();
            }

            if (ioService.mAcceptors.front().hasSubscriptions())
                throw UnitTestFail();
            if (ioService.mAcceptors.front().isListening())
                throw UnitTestFail();

            {
                Session c1(ioService, "127.0.0.1", 1212, SessionMode::Server);
                Session s1(ioService, "127.0.0.1", 1212, SessionMode::Client);
                auto ch1 = c1.addChannel();
                auto ch0 = s1.addChannel();


                bool throws = false;
                std::vector<u8> rr;
                auto f = ch1.asyncRecv(rr);
                auto thrd = std::thread([&]() {
                    //std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    ch1.cancel();
                });

                try { f.get(); }
                catch (...) { throws = true; }

                thrd.join();

                if (throws == false)
                    throw UnitTestFail("" LOCATION);

            }
            if (ioService.mAcceptors.front().hasSubscriptions())
                throw UnitTestFail();
            if (ioService.mAcceptors.front().isListening())
                throw UnitTestFail();

            {
                Session c1(ioService, "127.0.0.1", 1212, SessionMode::Server);
                auto ch1 = c1.addChannel();

                std::vector<u8> rr(10);
                auto f = ch1.asyncSendFuture(rr.data(), rr.size());

                auto thrd = std::thread([&]() {
                    //std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    ch1.cancel();
                });

                bool throws = false;
                try {
                    f.get();
                }
                catch (...) { throws = true; }

                thrd.join();
                if (throws == false)
                    throw UnitTestFail(LOCATION);

                if (ch1.isConnected())
                    throw UnitTestFail(LOCATION);

            }

            if (ioService.mAcceptors.front().hasSubscriptions())
                throw UnitTestFail();
            if (ioService.mAcceptors.front().isListening())
                throw UnitTestFail();

        }

        //std::cout << t << std::endl << std::endl;
    }

    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_ServerMode_Test);
    void BtNetwork_ServerMode_Test()
    {
        u64 numConnect = 25;
        IOService ioService(0);
        std::vector<std::array<Channel, 2>> srvChls(numConnect), clientChls(numConnect);

        for (u64 i = 0; i < numConnect; ++i)
        {
            
            //std::cout << " " <<i<<std::flush;
            Session s1(ioService, "127.0.0.1", 1212, SessionMode::Server);
            Session c1(ioService, "127.0.0.1", 1212, SessionMode::Client);
            srvChls[i][0] = s1.addChannel();
            srvChls[i][1] = s1.addChannel();
            clientChls[i][0] = c1.addChannel();
            clientChls[i][1] = c1.addChannel();

            //std::cout << "x" <<std::flush;
            std::string m0("c0");
            
            //if(i == 62 || i == 3)
            //{
            //    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            //    std::cout << "client\n==========================\n"<<
            //    clientChls[i][0].mBase->mLog << "\n\nserver\n==============================\n"
            //    << srvChls[i][0].mBase->mLog << "\n===============================\n\nAcceptor\n"
            //    << srvChls[i][0].mBase->mSession->mAcceptor->mLog << "\n==============================="<< std::endl ;
            //
            //}
            
            clientChls[i][0].asyncSend(std::move(m0));
            //std::cout << "y" <<std::flush;
            std::string m1("c1");
            clientChls[i][1].asyncSend(std::move(m1));
            //std::cout << "z" <<std::flush;
        }

        for (u64 i = 0; i < numConnect; ++i)
        {
            std::string m;
            srvChls[i][0].recv(m);
            if (m != "c0") throw UnitTestFail();
            srvChls[i][1].recv(m);
            if (m != "c1") throw UnitTestFail();
        }
        /////////////////////////////////////////////////////////////////////////////

        for (u64 i = 0; i < numConnect; ++i)
        {
            //ıstd::cout << " " <<i<<std::flush;
            Session s1(ioService, "127.0.0.1", 1212, SessionMode::Server);
            Session c1(ioService, "127.0.0.1", 1212, SessionMode::Client);
            clientChls[i][0] = c1.addChannel();
            clientChls[i][1] = c1.addChannel();

            srvChls[i][0] = s1.addChannel();
            srvChls[i][1] = s1.addChannel();

            //std::cout << "a" <<std::flush;
            std::string m0("c0");
            srvChls[i][0].asyncSend(std::move(m0));
 
            //std::cout << "b" <<std::flush;
            std::string m1("c1");
            srvChls[i][1].asyncSend(std::move(m1));

            //std::cout << "c" <<std::flush;
        }
        //auto s = ioService.mAcceptors.size();
        //auto& a = ioService.mAcceptors.front();
        //auto thrd = std::thread([&]() {
        //	//while (stop == false)
        //	//{
        //		std::this_thread::sleep_for(std::chrono::seconds(1));
        //		for (auto& group : a.mAnonymousClientEps)
        //		{
        //			std::cout << "anClient: ";
        //			group.print();
        //		}
        //		for (auto& group : a.mAnonymousServerEps)
        //		{
        //			std::cout << "anServer: ";
        //			group.print();
        //		}
        //		for (auto& group : a.mSessionGroups)
        //		{
        //			std::cout << "Group: ";
        //			group.second.print();
        //		}
        //	//}
        //});

        for (u64 i = 0; i < numConnect; ++i)
        {
            std::string m;
            clientChls[i][0].recv(m);
            if (m != "c0") throw UnitTestFail();
            clientChls[i][1].recv(m);
            if (m != "c1") throw UnitTestFail();

        }

        //thrd.join();
    }

    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_Connect1_Test);
    void BtNetwork_Connect1_Test()
    {
        setThreadName("Test_Host");

        std::string channelName{ "TestChannel" };
        std::string msg{ "This is the message" };

        IOService ioService(0);
        Channel chl1, chl2;
        auto thrd = std::thread([&]()
        {
            setThreadName("Test_Client");

            Session endpoint(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
            chl1 = endpoint.addChannel(channelName, channelName);

            std::string recvMsg;
            chl1.recv(recvMsg);

            if (recvMsg != msg) throw UnitTestFail();

            chl1.asyncSend(std::move(recvMsg));
        });

        Session endpoint(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");
        chl2 = endpoint.addChannel(channelName, channelName);

        chl2.asyncSend(msg);

        std::string clientRecv;
        chl2.recv(clientRecv);

        thrd.join();
        if (clientRecv != msg) throw UnitTestFail();

        //std::cout << "chl1: " << chl1.mBase->mLog << std::endl;


        //std::cout << "acpt: " << ioService.mAcceptors.begin()->mLog << std::endl;
        //std::cout << "chl2: " << chl2.mBase->mLog << std::endl;
    }


    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_OneMegabyteSend_Test);
    void BtNetwork_OneMegabyteSend_Test()
    {
        setThreadName("Test_Host");

        std::string channelName{ "TestChannel" };
        std::string msg{ "This is the message" };
        std::vector<u8> oneMegabyte((u8*)msg.data(), (u8*)msg.data() + msg.size());
        oneMegabyte.resize(1000000);

        memset(oneMegabyte.data() + 100, 0xcc, 1000000 - 100);

        IOService ioService(0);

        auto thrd = std::thread([&]()
        {
            setThreadName("Test_Client");

            Session endpoint(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
            Channel chl = endpoint.addChannel(channelName, channelName);

            std::vector<u8> srvRecv;
            chl.recv(srvRecv);

            auto act = chl.getTotalDataRecv();
            auto exp = oneMegabyte.size() + 4;
            if (act != exp)
                throw UnitTestFail("channel recv statistics incorrectly increased." LOCATION);


            if (srvRecv != oneMegabyte) throw UnitTestFail();

            chl.asyncSend(std::move(srvRecv));
        });


        Finally f([&] { thrd.join(); });


        Session endpoint(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");
        auto chl = endpoint.addChannel(channelName, channelName);


        if (chl.getTotalDataSent() != 0)
            throw UnitTestFail("channel send statistics incorrectly initialized." LOCATION);
        if (chl.getTotalDataRecv() != 0)
            throw UnitTestFail("channel recv statistics incorrectly initialized." LOCATION);


        std::vector<u8> clientRecv;
        chl.asyncSend(oneMegabyte);
        chl.recv(clientRecv);

        if (chl.getTotalDataSent() != oneMegabyte.size() + 4)
            throw UnitTestFail("channel send statistics incorrectly increased." LOCATION);
        if (chl.getTotalDataRecv() != oneMegabyte.size() + 4)
            throw UnitTestFail("channel recv statistics incorrectly increased." LOCATION);

        chl.resetStats();

        if (chl.getTotalDataSent() != 0)
            throw UnitTestFail("channel send statistics incorrectly reset." LOCATION);
        if (chl.getTotalDataRecv() != 0)
            throw UnitTestFail("channel recv statistics incorrectly reset." LOCATION);

        if (clientRecv != oneMegabyte)
            throw UnitTestFail();




    }


    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_ConnectMany_Test);
    void BtNetwork_ConnectMany_Test()
    {
        //InitDebugPrinting();
        setThreadName("Test_Host");

        std::string channelName{ "TestChannel" };

        u64 numChannels(15);
        u64 messageCount(15);

        bool print(false);

        std::vector<u8> buff(64);

        buff.data()[14] = 3;
        buff.data()[24] = 6;
        buff.data()[34] = 8;
        buff.data()[44] = 2;

        std::thread serverThrd = std::thread([&]()
        {
            IOService ioService;
            setThreadName("Test_client");

            Session endpoint(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");

            std::vector<std::thread> threads;

            for (u64 i = 0; i < numChannels; i++)
            {
                auto chl = endpoint.addChannel();
                threads.emplace_back([i, &buff, chl, messageCount, print, channelName]()mutable
                {
                    setThreadName("Test_client_" + std::to_string(i));
                    std::vector<u8> mH;

                    for (u64 j = 0; j < messageCount; j++)
                    {
                        chl.recv(mH);
                        if (buff != mH)
                        {
                            std::cout << "-----------failed------------" LOCATION << std::endl;
                            throw UnitTestFail();
                        }
                        chl.asyncSend(std::move(mH));
                    }

                });
            }


            for (auto& thread : threads)
                thread.join();
        });

        IOService ioService;

        Session endpoint(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

        std::vector<std::thread> threads;

        for (u64 i = 0; i < numChannels; i++)
        {
            auto chl = endpoint.addChannel();
            threads.emplace_back([i, chl, &buff, messageCount, print, channelName]() mutable
            {
                setThreadName("Test_Host_" + std::to_string(i));
                std::vector<u8> mH(buff);

                for (u64 j = 0; j < messageCount; j++)
                {
                    chl.asyncSendCopy(mH);
                    chl.recv(mH);

                    if (buff != mH)
                    {
                        std::cout << "-----------failed------------" LOCATION << std::endl;
                        throw UnitTestFail();
                    }
                }
            });
        }



        for (auto& thread : threads)
            thread.join();

        serverThrd.join();
    }


    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_CrossConnect_Test);
    void BtNetwork_CrossConnect_Test()
    {
        const block send = _mm_set_epi64x(123412156, 123546);
        const block recv = _mm_set_epi64x(7654333, 8765433);

        auto thrd = std::thread([&]() {
            IOService ioService(0);
            Session endpoint(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");


            auto sendChl1 = endpoint.addChannel("send", "recv");
            auto recvChl1 = endpoint.addChannel("recv", "send");

            block temp;

            sendChl1.asyncSendCopy(send);
            recvChl1.recv(temp);

            if (neq(temp, send))
                throw UnitTestFail();

            recvChl1.asyncSendCopy(recv);
            sendChl1.recv(temp);

            if (neq(temp, recv))
                throw UnitTestFail();

            recvChl1.close();
            sendChl1.close();

            endpoint.stop();

            ioService.stop();
        });
        IOService ioService(0);
        Session endpoint(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");


        auto recvChl0 = endpoint.addChannel("recv", "send");
        auto sendChl0 = endpoint.addChannel("send", "recv");

        block temp;

        sendChl0.asyncSendCopy(send);
        recvChl0.recv(temp);

        if (neq(temp, send))
            throw UnitTestFail();

        recvChl0.asyncSendCopy(recv);
        sendChl0.recv(temp);

        if (neq(temp, recv))
            throw UnitTestFail();


        thrd.join();
    }

    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_ManySessions_Test);
    void BtNetwork_ManySessions_Test()
    {
        u64 nodeCount = 10;
        u32 basePort = 1212;
        std::string ip("127.0.0.1");
        //InitDebugPrinting();
        IOService ioService(0);

        std::vector<std::thread> nodeThreads(nodeCount);

        setThreadName("main");
        bool failed = false;
        for (u64 i = 0; i < nodeCount; ++i)
        {
            nodeThreads[i] = std::thread([&, i]() {

                setThreadName("node" + std::to_string(i));


                u32 port;// = basePort + i;
                ioService.showErrorMessages(true);

                std::list<Session> sessions;
                std::vector<Channel> channels;

                for (u64 j = 0; j < nodeCount; ++j)
                {
                    if (j != i)
                    {
                        SessionMode host = i > j ? SessionMode::Server : SessionMode::Client;
                        std::string name("endpoint:");
                        if (host == SessionMode::Server)
                        {
                            name += std::to_string(i) + "->" + std::to_string(j);
                            port = basePort;// t + (u32)i;
                        }
                        else
                        {
                            name += std::to_string(j) + "->" + std::to_string(i);
                            port = basePort;// +(u32)j;
                        }

                        sessions.emplace_back(ioService, ip, port, host, name);

                        channels.push_back(sessions.back().addChannel("chl", "chl"));
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
                    channels[j].send(std::move(msg));
                }

                std::string expected = "hello" + std::to_string(i);

                for (auto& chl : channels)
                {
                    std::string msg;
                    chl.recv(msg);

                    if (msg != expected)
                        failed = true;
                }

            });
        }

        for (u64 i = 0; i < nodeCount; ++i)
            nodeThreads[i].join();

        if (failed)
            throw UnitTestFail();
    }

    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_AsyncConnect_Test);
    void BtNetwork_AsyncConnect_Test()
    {
        setThreadName("Test_Host");

        IOService ioService(4);
        Channel chl1, chl2;
        try {

            std::string channelName{ "TestChannel" };
            std::string msg{ "This is the message" };


            Session ep1(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
            chl1 = ep1.addChannel(channelName, channelName);

            if (chl1.isConnected() == true) throw UnitTestFail();


            Session ep2(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

            if (chl1.isConnected() == true) throw UnitTestFail();

            //std::cout << "add 2" << std::endl;
            chl2 = ep2.addChannel(channelName, channelName);

            chl1.waitForConnection();

            if (chl1.isConnected() == false) throw UnitTestFail();
            chl2.waitForConnection();
        }
        catch (...)
        {

            //std::cout << "done" << std::endl;

            //std::cout << "chl1: " << chl1.mBase->mLog << std::endl;

            //int aa = 0;
            //for (auto& a : ioService.mAcceptors)
            //{
            //    std::cout << "acpt"<<aa++<<": " << a.mLog << std::endl;
            //}
            //std::cout << "chl2: " << chl2.mBase->mLog << std::endl;
            throw;
        }

    }

    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_std_Containers_Test);
    void BtNetwork_std_Containers_Test()
    {
        setThreadName("Test_Host");
        std::string channelName{ "TestChannel" }, msg{ "This is the message" };
        IOService ioService;

        Session ep1(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
        Session ep2(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

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


    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_bitVector_Test);
    void BtNetwork_bitVector_Test()
    {
        setThreadName("Test_Host");
        std::string channelName{ "TestChannel" }, msg{ "This is the message" };
        IOService ioService;

        Session ep1(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
        Session ep2(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

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



    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_recvErrorHandler_Test);
    void BtNetwork_recvErrorHandler_Test()
    {


        setThreadName("Test_Host");
        std::string channelName{ "TestChannel" }, msg{ "This is the message" };
        IOService ioService;

        ioService.showErrorMessages(false);

        Session ep1(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
        Session ep2(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

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
        catch (BadReceiveBufferSize& e)
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

    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_closeOnError_Test);
    void BtNetwork_closeOnError_Test()
    {

        bool throws = false;
        try {

            setThreadName("Test_Host");
            std::string channelName{ "TestChannel" }, msg{ "This is the message" };
            IOService ioService;

            ioService.showErrorMessages(false);

            Session ep1(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
            Session ep2(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

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
        catch (std::runtime_error& e)
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
            ioService.showErrorMessages(false);

            Session ep1(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
            Session ep2(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

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
        catch (std::runtime_error& e)
        {
            throws = true;
        }


        if (throws == false)
        {
            throw UnitTestFail("no throw");
        }


    }

    void BtNetwork_clientClose_Test()
    {
        u64 trials(100);
        u64 count = 0;

        for (u64 i = 0; i < trials; ++i)
        {
            IOService ios;
            ios.mPrint = false;

            Session server(ios, "127.0.0.1", 1212, SessionMode::Server);
            Session client(ios, "127.0.0.1", 1212, SessionMode::Client);


            auto sChl = server.addChannel();
            auto cChl = client.addChannel();

            int k(0);
            cChl.send(k);
            sChl.recv(k);

            std::vector<u8> kk;
            sChl.asyncRecv(kk, [&](const error_code& ec) {
                if (ec)
                    ++count;
                //std::cout << " ec " << ec.message() << std::endl;
                }
            );

            cChl.close();
        }

        if (count != trials)
            throw UnitTestFail(LOCATION);
    }


    class Pipe
    {
    public:

        //struct FP
        //{
        //    FP() 
        //        :mF(mP.get_future())
        //    {}

        //    std::promise<std::vector<u8>> mP;
        //    std::future<std::vector<u8>> mF;
        //};

        std::mutex mMtx;
        std::list<std::vector<u8>> mBuff;



        Pipe() = default;

        Pipe* mOther;

        void join(Pipe& o)
        {
            mOther = &o;
            o.mOther = this;
        }


        void send(u8* d, u64 s)
        {
            std::lock_guard<std::mutex> l(mOther->mMtx);
            mOther->mBuff.emplace_back(d, d + s);
        }


        void recv(u8* d, u64 s)
        {
            while (true)
            {

                {
                    std::lock_guard<std::mutex> l(mMtx);
                    if (mBuff.size())
                    {
                        if (mBuff.front().size() == s)
                        {
                            memcpy(d, mBuff.front().data(), s);
                            mBuff.pop_front();
                            return;
                        }
                        else
                        {
                            throw std::runtime_error(LOCATION);
                        }
                    }
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    };

    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_SocketInterface_Test);
    void BtNetwork_SocketInterface_Test()
    {
        setThreadName("main");
        try {
            std::string channelName{ "TestChannel" }, msg{ "This is the message" };
            IOService ioService;
            IOService ioService2;

            ioService.showErrorMessages(false);

            u64 trials = 100;

            for (u64 i = 0; i < trials; ++i)
            {

                Session ep1(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
                Session ep2(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

                auto chl1 = ep1.addChannel(channelName, channelName);
                auto chl2 = ep2.addChannel(channelName, channelName);

                //////////////////////////////////////////////////////////////////////////
                //////////////////////////////////////////////////////////////////////////
                chl1.waitForConnection();
                chl2.waitForConnection();

                Pipe p1;
                Pipe p2;
                p2.join(p1);

                Channel ichl1(ioService2, new SocketAdapter<Channel>(chl1));
                Channel ichl2(ioService2, new SocketAdapter<Channel>(chl2));


                ichl1.asyncSendCopy(msg);

                std::string msg2;
                ichl2.recv(msg2);

                if (msg != msg2)
                {
                    throw UnitTestFail(LOCATION);
                }
            }
        }
        catch (std::exception& e)
        {
            std::cout << "sss" << e.what() << std::endl;
        }
    }


    //OSU_CRYPTO_ADD_TEST(globalTests, BtNetwork_RapidConnect_Test);
    void BtNetwork_RapidConnect_Test()
    {

        u64 trials = 100;
        std::string channelName{ "TestChannel" }, msg{ "This is the message" };
        IOService ioService;

        ioService.showErrorMessages(false);

        for (u64 i = 0; i < trials; ++i)
        {

            try {

                Session ep1(ioService, "127.0.0.1", 1212, SessionMode::Client, "endpoint");
                Session ep2(ioService, "127.0.0.1", 1212, SessionMode::Server, "endpoint");

                auto chl1 = ep1.addChannel(channelName, channelName);
                auto chl2 = ep2.addChannel(channelName, channelName);

                chl1.asyncSendCopy(msg);

                std::string msg2;
                chl2.recv(msg2);

                if (msg != msg2)
                {
                    throw UnitTestFail(LOCATION);
                }
            }
            catch (std::exception& e)
            {
                std::cout << "sss" << e.what() << std::endl;
                throw;
            }
        }

    }


    class Base {
    public:
        virtual ~Base() {}
        virtual std::string print() = 0;
    };
    template<int N>
    class MoveOnly : public Base
    {
    public:
        MoveOnly() = delete;
        MoveOnly(std::string s) :mStr(std::move(s)) {};
        MoveOnly(const MoveOnly&) = delete;
        MoveOnly(MoveOnly&&m) = default;


        std::string print() override { return mStr; }

        std::string mStr;
    };

    class Large : public Base
    {
    public:
        std::array<int, 100> _;
        Large() = default;
        Large(Large&&) = default;

        std::string print() override { return "Large"; }

    };

    //OSU_CRYPTO_ADD_TEST(globalTests, SBO_ptr_test);
    void SBO_ptr_test()
    {
        auto ss = std::string("s");



        {
            SBO_ptr<Base> oo;
            oo.New<MoveOnly<4>>(ss);
            bool b = oo.isSBO();
            if (!b) throw std::runtime_error(LOCATION);

            auto s1 = oo->print();
            if (s1 != ss) throw std::runtime_error(LOCATION);

            {
                SBO_ptr<Base> oo2;
                oo2 = std::move(oo);
                auto s2 = oo2->print();
                if (s2 != ss) throw std::runtime_error(LOCATION);

                {
                    SBO_ptr<Base> oo3(std::move(oo2));
                    auto s3 = oo3->print();
                    if (s3 != ss) throw std::runtime_error(LOCATION);
                }
            }
        }

        {
            SBO_ptr<Base> oo;
            oo.New<Large>();
            bool b = oo.isSBO();
            if (b) throw std::runtime_error(LOCATION);

            auto s1 = oo->print();
            if (s1 != "Large") throw std::runtime_error(LOCATION);

            {
                SBO_ptr<Base> oo2;
                oo2 = std::move(oo);

                auto s2 = oo2->print();
                if (s2 != "Large") throw std::runtime_error(LOCATION);

                {
                    SBO_ptr<Base> oo3(std::move(oo2));
                    auto s3 = oo3->print();

                    if (s3 != "Large") throw std::runtime_error(LOCATION);
                }
            }
        }
    }
}
