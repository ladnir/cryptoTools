#include <cryptoTools/Common/config.h>
#ifdef ENABLE_BOOST

#include "Network.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>


using namespace osuCrypto;


void networkTutorial()
{
    std::cout << "\n"
        << "/*#####################################################\n"
        << "##                 Network tutorial                  ##\n"
        << "/*#####################################################" << std::endl;


    /*#####################################################
    ##                      Setup                        ##
    #####################################################*/


    /*  --------------- Introduction --------------------\
    |  													 |
    |  The general framework is to have pairs of parties |
    |    establish a "session," which in turn can have   |
    |           several channels (sockets). 			 |
    | 													 |
    \ --------------------------------------------------*/


    // create network I/O service with 4 background threads.
    // This object must stay in scope until everything is cleaned up.
    IOService ios(4);

    // By default, ios will print when things so wrong
    // such as a bad buffer size or connection close.
    // However, some applications handle these errors
    // gracefully in which case you will want to set
    // this to false and avoid unwanted printing.
    ios.showErrorMessages(true);

    auto ip = std::string("127.0.0.1");
    auto port = 1212;

    std::string serversIpAddress = ip + ':' + std::to_string(port);

    // Optional: Session names can be used to help the network 
    // identify which sessions should be paired up. This is used
    // when there are several "services" offered on a single port.
    // SessionHint is used to identify the "service" to connect with.
    std::string sessionHint = "party0_party1";

    // Create a pair of sessions that connect to eachother. Note that
    // the sessionHint parameter is options.
    Session server(ios, serversIpAddress, SessionMode::Server, sessionHint);
    Session client(ios, serversIpAddress, SessionMode::Client, sessionHint);

    // Actually get the channel that can be used to communicate on.
    Channel chl0 = client.addChannel();
    Channel chl1 = server.addChannel();

    // Two sessions can have many channels, each an independent socket.
    {
        Channel chl0b = client.addChannel();
        Channel chl1b = server.addChannel();
    }

    // Above, the channels are connected in the order that they are declared. Alternatively
    // explicit names can be provided. This channel pair are connected regardless of order.
    {
        std::string channelName = "channelName";
        Channel namedChl0 = client.addChannel(channelName);
        Channel namedChl1 = server.addChannel(channelName);
    }

    // We now have a pair of channels, but it is possible that they have yet
    // to actually connect to each other in the background. To test that the
    // channel has a completed the connection, we can do
    std::cout << "Channel connected = " << chl0.isConnected() << std::endl;


    // To block until for 100 milliseconds for the connection to actually open.
    std::chrono::milliseconds timeout(100);
    bool open = chl0.waitForConnection(timeout);

    // We can also set a callback for when connection (or error)
    // happens. If error, ec will hold the reason.
    chl0.onConnect([](const error_code& ec) {
        if (ec)
            std::cout << "chl0 failed to connect: " << ec.message() << std::endl;
        });

    if (open == false)
    {
        // Wait until the channel is open. This will throw 
        // on an connection error.
        chl0.waitForConnection();
    }

    // This call will now always return true.
    std::cout << "Channel connected = " << chl0.isConnected() << std::endl;



    /*#####################################################
    ##                   The Basics                      ##
    #####################################################*/

    // There are several ways and modes to send and receive data.
    // The simplest mode is blocking, i.e. when data is sent, the caller
    // blocks until all data is sent.

    // For example:
    {
        std::vector<int> data{ 0,1,2,3,4,5,6,7 };
        chl0.send(data);


        std::vector<int> dest;
        chl1.recv(dest);
    }


    // It is now the case that data == dest. When data is received,
    // the Channel will call dest.resize(8)

    // In the example above,
    // the Channel can tell that data is an STL like container.
    // That is, it has member functions and types:
    //
    //   Container<T>::data() -> Container<T>::pointer
    //   Container<T>::size() -> Container<T>::size_type
    //   Container<T>::value_type
    //
    // Anything with these traits can be used, e.g. std::array<T,N>.
    {
        std::array<int, 4> data{ 0,1,2,3 };
        chl0.send(data);

        std::array<int, 4> dest;
        chl1.recv(dest);
    }

    // You can also use a pointer and length to send and receive data.
    // In the case that the data being recieved is the wrong size,
    // Channel::recv(...) will throw.
    {
        std::array<int, 4> data{ 0,1,2,3 };
        chl0.send(data.data(), data.size());


        std::array<int, 4> dest;
        chl1.recv(dest.data(), dest.size()); // may throw
    }

    // One issue with this approach is that the call
    //
    //        chl0.send(...);
    //
    // blocks until all of the data has been sent over the network. If data
    // is large, or if we send many things, then this may take awhile.



    /*#####################################################
    ##                  Asynchronous                     ##
    #####################################################*/

    // We can overcome this with Asynchronous IO. These calls do not block.
    // In this example, note that std::move semantics are used.
    {
        std::vector<int> data{ 0,1,2,3,4,5,6,7 };
        chl0.asyncSend(std::move(data)); // will not block.


        std::vector<int> dest;
        chl1.recv(dest); // will block.
    }

    // the call
    //
    //  Channel::asyncSend(...);
    //
    // does not block. Instead, it "steals" the data contained inside
    // the vector. As a result, data is empty after this call.

    // When move semantics are not supported by Container or if you want to
    // share ownership of the data, we can use a unique/shared pointer.
    {
        std::unique_ptr<std::vector<int>> unique{ new std::vector<int>{0,1,2,3,4,5,6,7 } };
        chl0.asyncSend(std::move(unique)); // will not block.

        // unique = empty

        std::shared_ptr<std::vector<int>> shared{ new std::vector<int>{0,1,2,3,4,5,6,7 } };
        chl0.asyncSend(std::move(shared)); // will not block.

        // shared's refernce counter = 2.

        std::vector<int> dest;
        chl1.recv(dest); // block for unique's data.
        chl1.recv(dest); // block for shared's data.

        // shared's refernce counter = 1.
    }


    // We can also perform asynchronous receive. In this case, we will tell the channel
    // where to store data in the future...
    {
        std::vector<int> dest;
        auto future = chl1.asyncRecv(dest); // will not block.

        // dest == {}

        // in the future, send the data.
        std::vector<int> data{ 0,1,2,3,4,5,6,7 };
        chl0.asyncSend(std::move(data)); // will not block.

        // dest == ???

        future.get(); // will block

        // dest == {0,1,...,7}
    }
    // The above asyncRecv(...) is not often used, but it has at least one
    // advantage. The implementation of Channel is optimize to store the
    // data directly into dest. As opposed to buffering it interally, and
    // the later copying it to dest when Channel::recv(...) is called.


    // Channel::asyncSend(...) also support the pointer length interface.
    // In this case, it is up to the user to ensure that the lifetime
    // of data is larger than the time required to send. In this case, we are
    // ok since chl1.recv(...) will block until this condition is true.
    {
        std::array<int, 4> data{ 0,1,2,3 };
        chl0.asyncSend(data.data(), data.size());


        std::vector<int> dest;
        chl1.recv(dest);
    }


    // As an additional option for this interface, a call back
    // function can be provided. This call back will be called
    // once the data has been sent.
    {
        int size = 4;
        u8* data = new u8[size]();

        chl0.asyncSend(span<u8>(data, size), [data]()
            {
                // we are done with data now, delete it.
                delete[] data;
            });


        std::vector<u8> dest;
        chl1.recv(dest);
    }

    // Finally, there is also a method to make a deep copy and send asynchronously.
    {
        std::vector<int> data{ 0,1,2,3,4,5,6,7 };

        chl0.asyncSendCopy(data);


        std::vector<int> dest;
        chl1.recv(dest);
    }



    /*#####################################################
    ##                   Cancelation                     ##
    #####################################################*/

    // If a connection is never established when the channel
    // is destructed it will block. This can also happen if the
    // client tries to connect to a server that does not exists.
    // For example,
    {
        Session session(ios, "127.0.0.1:1515", SessionMode::Server);
        Channel emptyChannel = session.addChannel();

        // no corresponding client channel

        // If we then call
        //     emptyChannel.recv(...);
        //     emptyChannel.waitForConnection();
        // or a similar call, the program will block forever.

        // if we fail to get a connection, cancel() should be called to prevent the channel 
        // from blocking when it is destructed.
        if (emptyChannel.isConnected() == false)
            emptyChannel.cancel();
    }

    // We can also cancel pending operations. However, this will also
    // close the channel making it unusable. 
    {
        Channel tempChl0 = Session(ios, "127.0.0.1:1515", SessionMode::Server).addChannel();
        Channel tempChl1 = Session(ios, "127.0.0.1:1515", SessionMode::Client).addChannel();

        // schedule a recv operation what will never complete.
        std::vector<u8> buff;
        auto asyncOp = tempChl0.asyncRecv(buff);

        // Would block forever.
        //    asyncOp.get();

        // We can cancel this operation by calling
        tempChl0.cancel();

        // This will now throw...
        //    asyncOp.get();
    }


    /*#####################################################
    ##                 Error Handling                    ##
    #####################################################*/

    // While not required, it is possible to recover from errors that
    // are thrown when the receive buffer does not match the incoming
    // data and can not be resized. Consider the following example
    {
        Channel chl0e = client.addChannel();
        Channel chl1e = server.addChannel();

        std::array<int, 4> data{ 0,1,2,3 };
        chl0e.send(data);

        std::array<int, 2> dest;
        try
        {
            // will throw, dest.size() != dat.size(); and no resize() member.
            chl1e.recv(dest);
        }
        catch (BadReceiveBufferSize&)
        {
            // close the channel...
        }
    }


    /*#####################################################
    ##                   Server Mode                     ##
    #####################################################*/

    // It is also possible to accept many session with independent
    // clients. This is done by having the server set up several session.
    // Each will correspond to a single party.

    u64 numSession = 10;

    for (u64 i = 0; i < numSession; ++i)
    {
        // The server will create many sessions, each will find one 
        // of the clients. Optionally a sessionHint/serviceName can be 
        // provided
        Session perPartySession(ios, serversIpAddress, SessionMode::Server /* , serviceName */);

        // On some other thread/program/computer, a client can complete the
        // session and add a channel.
        {
            Channel clientChl = Session(ios, serversIpAddress, SessionMode::Client /* , serviceName */).addChannel();
            clientChl.send(std::string("message"));
        }

        // Create a channel for this session, even before the client has connected.
        Channel serverChl = perPartySession.addChannel();

        std::string msg;
        serverChl.recv(msg);
    }


    /*#####################################################
    ##                  TLS channels                     ##
    #####################################################*/

    // Most realistic protocols require TLS to acheive their
    // security guarantees. This is supported in cryptoTools
    // by the WolfSSL or OpenSSL libraries.
#ifdef ENABLE_WOLFSSL
    {
        error_code ec;
        TLSContext sctx, cctx;

        // Intitialize the context. The mode can either
        // be client/server specific or it can allow connections
        // of both types.
        sctx.init(TLSContext::Mode::Server, ec);

        // If we want client side authentication then we call this.
        sctx.requestClientCert(ec);

        // Load the CA's that we should respect.
        sctx.loadCert(sample_ca_cert_pem, ec);

        // Also see.
        //sctx.loadCertFile("path/to/ca.pem", ec);

        // Load out own private key and cert.
        sctx.loadKeyPair(sample_server_cert_pem, sample_server_key_pem, ec);

        // Also see
        //sctx.loadKeyPairFile("path/to/myCert.pem", "path/to/myKey.pem", ec);

        // Similar for the server. Except we can't call requestClientCert(...);
        cctx.init(TLSContext::Mode::Client, ec);
        cctx.loadCert(sample_ca_cert_pem, ec);
        cctx.loadKeyPair(sample_server_cert_pem, sample_server_key_pem, ec);

        // In general you should check the error_code output parmeter...

        // We can now use these TLS context objects to create sessions.
        Session tlsSes0(ios, ip, port, SessionMode::Server, sctx);
        Session tlsSes1(ios, ip, port, SessionMode::Client, cctx);

        Channel tlsChl0 = tlsSes0.addChannel();
        Channel tlsChl1 = tlsSes1.addChannel();

        // wait for the TLS handshake to complete.
        tlsChl0.waitForConnection();

        // We can now get the common name of the other party.
        std::string commonName = tlsChl0.commonName();


        // use the TLS channel.
    }
#endif // ENABLE_WOLFSSL

    /*#####################################################
    ##              Using your own socket                ##
    #####################################################*/

    // It is also possible to use your own socket implementation
    // with Channel. There are three methods for doing this. First,
    // the osuCrypto::SocketAdapter<T> class can be used with your
    // socket and then provided to a Channel with an osuCrypto::IOService
    //
    // SocketAdapter<T> requires that T implements
    //
    //    void send(const char* data, u64 size);
    //    void recv(      char* data, u64 size);
    //
    // Or a signature that is convertable from those parameter.

    {
        // Lets say you have a socket type that implements send(...),
        // recv(...) and that is called YourSocketType
        typedef Channel YourSocketType;

        // Assuming your socket meets these rquirements, then a Channel
        // can be constructed as follows. These Channels will function
        // equivolently to the original ones.
        //
        // WARNING: The lifetime of the SocketAdapter<T> is managed by
        //	        the Channel.
        Channel aChl0(ios, new SocketAdapter<YourSocketType>(chl0));
        Channel aChl1(ios, new SocketAdapter<YourSocketType>(chl1));

        // We can now use the new channels
        std::array<int, 4> data{ 0,1,2,3 };
        aChl0.send(data);
        aChl1.recv(data);
    }

    // If your Socket type does not have these methods a custom adapter
    // will be required. The template SocketAdapter<T> implements the
    // interface SocketInterface in the <cryptoTools/Network/SocketAdapter.h>
    // file. You will also have to define a class that inherits the
    // SocketInterface class and implements:
    //
    //    void async_recv(span<boost::asio::mutable_buffer> buffers, io_completion_handle&& fn) override;
    //    void async_send(span<boost::asio::mutable_buffer> buffers, io_completion_handle&& fn) override;
    //
    // An example of this is LocalSocket which is in the header of this cpp file.
    // This socket type communicates over shared memory. And therefore only
    // works when communicating within a single program.
    {
        auto sockPair = LocalSocket::makePair();

        Channel aChl0(ios, sockPair[0]);
        Channel aChl1(ios, sockPair[1]);

        // We can now use the new channels
        std::array<int, 4> data{ 0,1,2,3 };
        aChl0.send(data);
        aChl1.recv(data);
    }


    /*#####################################################
    ##                   Statistics                      ##
    #####################################################*/

    // Print interesting information.
    std::cout
        << "   Session: " << chl0.getSession().getName() << std::endl
        << "   Channel: " << chl0.getName() << std::endl
        << "      Sent: " << chl0.getTotalDataSent() << std::endl
        << "  received: " << chl0.getTotalDataRecv() << std::endl;

    // Reset the data sent coutners.
    chl0.resetStats();



    /*#####################################################
    ##               OPTIONAL: Clean up                  ##
    #####################################################*/


    // close everything down in this order.
    chl0.close();
    chl1.close();

    server.stop();
    client.stop();

    ios.stop();
}

#endif
