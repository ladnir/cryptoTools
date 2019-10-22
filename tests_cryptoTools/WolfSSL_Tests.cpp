#include "WolfSSL_Tests.h"


extern "C" {
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <../wolfssl/IDE/WIN10/user_settings.h>
}
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
#include <array>
#include <stdio.h>
#include <iostream>
#include <thread>

#include <cryptoTools/Network/TLS.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/TestCollection.h>
using namespace oc;




/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

#define SVR_COMMAND_SIZE 256
#define throwEC(ec) {lout << "throwing " << ec.message() << " @ " <<LOCATION << std::endl; throw std::runtime_error(ec.message() + LOCATION);}

int client()
{
    u64 trials = 10;
    WolfContext ctx;
    error_code ec;
    //lout << "c 0" << std::endl;
    ctx.initClient(ec);
    if (ec) throwEC(ec);
    //lout << "c 1" << std::endl;
    ctx.loadCertFile(caCertFile, ec);
    //lout << "c 2" << std::endl;

    IOService ios;
    WolfSocket sock(ios.mIoService, ctx);
    //lout << "c 3" << std::endl;

    if (ec)
    {
        lout << "failed to load " << caCertFile << std::endl;
        throw std::runtime_error(ec.message());
    }

    boost::asio::ip::tcp::resolver resolver(ios.mIoService);
    boost::asio::ip::tcp::resolver::query query("127.0.0.1", "1212");
    boost::asio::ip::tcp::endpoint addr = *resolver.resolve(query);
   // lout << "c 4" << std::endl;

    u64 bt;
    sock.mSock.connect(addr, ec);
    if(!ec) sock.connect(ec);
    if (ec) throwEC(ec);

    //lout << "c connect" << std::endl;

    //lout << Color::Red << u64(&sock) << " connect " << std::endl << Color::Default;

    std::array<char, SVR_COMMAND_SIZE> msg;
    std::array<char, SVR_COMMAND_SIZE> reply;

    

    //while (fgets(msg.data(), sizeof(msg), stdin) != 0) {
    for(u64 i =0; i < trials; ++i){

        auto sendSz =1 + (rand() % (msg.size()-1));
        for (u64 j = 0; j < sendSz; ++j)
            msg[j] = j;

        boost::asio::mutable_buffer bufs[2];
        bufs[0] = boost::asio::mutable_buffer((char*)&sendSz, sizeof(int));
        bufs[1] = boost::asio::mutable_buffer(msg.data(), sendSz);
        sock.send(bufs, ec, bt);
        //lout << Color::Red << u64(&sock) << " sent " << std::endl << Color::Default;

        if (ec)
            throwEC(ec);



        if (strncmp(msg.data(), "quit", 4) == 0) {
            fputs("sending server shutdown command: quit!\n", stdout);
            break;
        }

        if (strncmp(msg.data(), "break", 5) == 0) {
            fputs("sending server session close: break!\n", stdout);
            break;
        }

        bufs[1] = boost::asio::mutable_buffer(reply.data(), sendSz);
        sock.recv({ &bufs[1], 1 }, ec, bt);
        //lout << Color::Red << u64(&sock) << " recv " << std::endl << Color::Default;

        if (ec)
            throwEC(ec);
        if (memcmp(reply.data(), msg.data(), sendSz) != 0)
        {
            std::cout << "bad echo message " << std::endl;
            throw std::runtime_error(LOCATION);
        }
    }

    return 0;
}



int server()
{
    try {

    int    ret = 0;
    int    shutDown = 0;
    word16 port = wolfSSLPort;


    IOService ios;
    boost::asio::ip::tcp::resolver resolver(ios.mIoService);
    boost::asio::ip::tcp::resolver::query query("127.0.0.1", "1212");
    boost::asio::ip::tcp::endpoint addr = *resolver.resolve(query);
    boost::asio::ip::tcp::acceptor accpt(ios.mIoService);

    //lout << "server 1" << std::endl;
    error_code ec;
    accpt.open(addr.protocol());
    accpt.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    //lout << "server 2" << std::endl;
    accpt.bind(addr, ec);
    if (ec)
    {
        lout << "ec bind " << ec.message() << std::endl;
        throw RTE_LOC;
    }
    accpt.listen(boost::asio::socket_base::max_connections, ec);
    if (ec)
    {
        lout << "ec listen " << ec.message() << std::endl;
        throw RTE_LOC;
    }


    //lout << "server 3" << std::endl;

    WolfContext ctx;
    ctx.initServer(ec);
    if (ec) throwEC(ec);

    ctx.loadKeyPairFile(svrCertFile, svrKeyFile, ec);

    if (ec)
    {
        lout << "failed to load server keys\n" 
            << svrCertFile << "\n" 
            << svrKeyFile << "\n"
            << "ec = " << ec.message() << std::endl;
        throw RTE_LOC;
    }

    //lout << "server 4" << std::endl;


    while (!shutDown) {

        std::array<char, SVR_COMMAND_SIZE> command;
        int     echoSz = 0;

        WolfSocket sock(ios.mIoService, ctx);
        //lout << "server 5" << std::endl;

        sock.setDHParamFile(dhParamFile, ec);
        if (ec) throwEC(ec);

        accpt.accept(sock.mSock, ec);

        if(!ec) sock.accept(ec);
        if (ec)
        {
            std::cout << "accept failed: " << ec.message() << std::endl;
            continue;
        }
        //lout << "s accept" << std::endl;

        //lout << Color::Green << u64(&sock) << " accepted " << std::endl << Color::Default;

        u64 bt;

        boost::asio::mutable_buffer bufs[1];

        while (true)
        {
            bufs[0] = boost::asio::mutable_buffer((char*)&echoSz, sizeof(int));
            sock.recv(bufs, ec, bt);

            //lout << Color::Green << u64(&sock) << " recvd size " << std::endl << Color::Default;


            if (ec)
            {
                //std::cout << Color::Green << "recv failed: " << ec.message() << std::endl << Color::Default;
                shutDown = true;
                break;
            }

            if (echoSz > command.size())
            {
                std::cout << Color::Green << "msg too large. " << std::endl << Color::Default;
                break;
            }

            bufs[0] = boost::asio::mutable_buffer(command.data(), echoSz);
            sock.recv(bufs, ec, bt);

            //lout << Color::Green << u64(&sock) << " recvd body " << std::endl << Color::Default;

            if (strncmp(command.data(), "quit", 4) == 0) {
                printf("client sent quit command: shutting down!\n");
                shutDown = 1;
                break;
            }
            else if (strncmp(command.data(), "break", 5) == 0) {
                printf("client sent break command: closing session!\n");
                break;
            }
            else if (strncmp(command.data(), "GET", 3) == 0) {
                const char resp[] =
                    "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n"
                    "<html><body BGCOLOR=\"#ffffff\"><pre>\r\n"
                    "greetings from wolfSSL\r\n</body></html>\r\n\r\n";

                echoSz = (int)strlen(resp) + 1;
                bufs[0] = boost::asio::mutable_buffer(command.data(), echoSz);
                strncpy(command.data(), resp, command.size());
            }
            else
            {
                command[echoSz] = 0;
                //lout << Color::Yellow << command.data() << std::endl;
            }

            sock.send(bufs, ec, bt);
            if (ec)
            {
                std::cout << "failed to send. " << ec.message() << std::endl;
            }

            //lout << Color::Green << u64(&sock) << " sent body " << std::endl << Color::Default;
        }

    }
    //lout << Color::Green << " server exit " << std::endl << Color::Default;
    }
    catch (...)
    {
        lout << "server threw" << std::endl;
    }
    return 0;
}

void wolf_echoServer_test(const osuCrypto::CLP& cmd)
{

    //StartTCP();
    //lout << "start" << std::endl;

    auto thrd = std::thread([] { server(); });

    //std::this_thread::sleep_for(std::chrono::seconds(1));
    try {
        client();
    }
    catch (...)
    {
        thrd.join();
        throw;
    }

    thrd.join();
}

void wolf_mutualAuth_test(const osuCrypto::CLP& cmd)
{

    word16 port = wolfSSLPort;
    error_code ec;
    IOService ios;
    u64 bt;

    boost::asio::ip::tcp::resolver resolver(ios.mIoService);
    boost::asio::ip::tcp::resolver::query query("127.0.0.1", "1212");
    boost::asio::ip::tcp::endpoint addr = *resolver.resolve(query);
    boost::asio::ip::tcp::acceptor accpt(ios.mIoService);
    accpt.open(addr.protocol());
    accpt.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    accpt.bind(addr, ec);
    if (ec) throwEC(ec);
    accpt.listen(boost::asio::socket_base::max_connections);


    WolfContext sctx;
    sctx.initServer(ec);
    if (ec) throwEC(ec);
    sctx.requestClientCert(ec);
    if (ec) throwEC(ec);
    sctx.loadCertFile(caCertFile, ec);
    if (ec) throwEC(ec);
    sctx.loadKeyPairFile(svrCertFile, svrKeyFile, ec);
    if (ec) throwEC(ec);


    WolfContext cctx;
    cctx.initClient(ec);
    if (ec) throwEC(ec);
    cctx.loadCertFile(caCertFile, ec);
    if (ec) throwEC(ec);
    cctx.loadKeyPairFile(svrCertFile, svrKeyFile, ec);
    if (ec) throwEC(ec);
    WolfSocket csock(ios.mIoService, cctx);
    csock.mSock.connect(addr, ec);
    if (ec) throwEC(ec);
    std::promise<error_code> prom;
    csock.async_connect([&](const error_code& ec) { 
        prom.set_value(ec); 
        });
    
    WolfSocket ssock(ios.mIoService, sctx);
    ssock.setDHParamFile(dhParamFile, ec);
    if (ec) throwEC(ec);

    accpt.accept(ssock.mSock, ec);
    if (ec) throwEC(ec);
    ssock.accept(ec);
    if (ec) { std::cout << "accept failed: " << ec.message() << std::endl; throwEC(ec); }
    
    ec = prom.get_future().get();
    if (ec) { std::cout << "connect failed: " << ec.message() << std::endl; throwEC(ec); }


    std::array<u8, 100> msg, resp;
    boost::asio::mutable_buffer bufs[1];
    bufs[0] = boost::asio::mutable_buffer(msg.data(), msg.size());
    ssock.send(bufs, ec, bt);
    if (ec) throwEC(ec);
    bufs[0] = boost::asio::mutable_buffer(resp.data(), resp.size());
    csock.recv(bufs, ec, bt);
    if (ec) throwEC(ec);
    bufs[0] = boost::asio::mutable_buffer(msg.data(), msg.size());
    csock.send(bufs, ec, bt);
    if (ec) throwEC(ec);
    bufs[0] = boost::asio::mutable_buffer(resp.data(), resp.size());
    ssock.recv(bufs, ec, bt);
    if (ec) throwEC(ec);
}

void wolf_channel_test(const osuCrypto::CLP& cmd)
{

    IOService ios;
    error_code ec;
    WolfContext sctx, cctx;

    if (!ec) sctx.initServer(ec);
    if (!ec) sctx.requestClientCert(ec);
    if (!ec) sctx.loadCertFile(caCertFile, ec);
    if (!ec) sctx.loadKeyPairFile(svrCertFile, svrKeyFile, ec);

    if (!ec) cctx.initClient(ec);
    if (!ec) cctx.loadCertFile(caCertFile, ec);
    if (!ec) cctx.loadKeyPairFile(svrCertFile, svrKeyFile, ec);

    if (ec) throwEC(ec);

    Session sses, cses;

    sses.start(ios, "127.0.0.1", 1212, SessionMode::Server, sctx);
    cses.start(ios, "127.0.0.1", 1212, SessionMode::Client, cctx);

    auto schl = sses.addChannel();
    auto cchl = cses.addChannel();

    std::array<char, 10> data{32,34,3,4,5,55,3}, data2;
    schl.send(data);
    cchl.recv(data);
    cchl.send(data);
    schl.recv(data2);
    if (data != data2)
        throw UnitTestFail(LOCATION);
    
}


void wolf_CancelChannel_Test()
{
    u64 trials = 3;

    error_code ec;
    WolfContext sctx, cctx;

    if (!ec) sctx.initServer(ec);
    if (!ec) sctx.requestClientCert(ec);
    if (!ec) sctx.loadCertFile(caCertFile, ec);
    if (!ec) sctx.loadKeyPairFile(svrCertFile, svrKeyFile, ec);

    if (!ec) cctx.initClient(ec);
    if (!ec) cctx.loadCertFile(caCertFile, ec);
    if (!ec) cctx.loadKeyPairFile(svrCertFile, svrKeyFile, ec);

    if (ec) throwEC(ec);

    for (u64 i = 0; i < trials; ++i)
    {
        IOService ioService;
        ioService.showErrorMessages(false);

        {
            Session c1(ioService, "127.0.0.1", 1212, SessionMode::Server, sctx);
            Session s1(ioService, "127.0.0.1", 1212, SessionMode::Client, cctx);
            auto ch1 = c1.addChannel("t2");
            auto ch0 = s1.addChannel("t2");

            int i = 8;
            ch0.send(i);
            ch1.recv(i);

            bool throws = false;
            std::vector<u8> rr;
            auto f = ch1.asyncRecv(rr);
            //auto thrd = std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(i));
            ch1.cancel();
            //});

            try { f.get(); }
            catch (...) { throws = true; }

            //thrd.join();

            if (throws == false)
            {
#ifdef ENABLE_NET_LOG
                std::cout << ch1.mBase->mLog << std::endl;
#endif
                throw UnitTestFail(LOCATION);
            }

        }

        if (ioService.mAcceptors.size() != 1)
            throw UnitTestFail(LOCATION);
        if (ioService.mAcceptors.front().hasSubscriptions())
            throw UnitTestFail(LOCATION);
        if (ioService.mAcceptors.front().isListening())
            throw UnitTestFail(LOCATION);

        {
            Session c1(ioService, "127.0.0.1", 1212, SessionMode::Server, sctx);
            Session s1(ioService, "127.0.0.1", 1212, SessionMode::Client, cctx);
            auto ch1 = c1.addChannel("t2");
            auto ch0 = s1.addChannel("t2");

            bool throws = false;
            std::vector<u8> rr;
            auto f = ch1.asyncRecv(rr);
            //auto thrd = std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(i));
            ch1.cancel();
            //});

            try { f.get(); }
            catch (...) { throws = true; }

            //thrd.join();

            if (throws == false)
            {
#ifdef ENABLE_NET_LOG
                std::cout << ch1.mBase->mLog << std::endl;
#endif
                throw UnitTestFail(LOCATION);
            }

        }

        if (ioService.mAcceptors.front().hasSubscriptions())
            throw UnitTestFail(LOCATION);
        if (ioService.mAcceptors.front().isListening())
            throw UnitTestFail(LOCATION);

    }

    //std::cout << t << std::endl << std::endl;
}
