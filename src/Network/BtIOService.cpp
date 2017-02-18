#include <cryptoTools/Network/BtIOService.h>
#include <cryptoTools/Common/ByteStream.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/BtAcceptor.h>
#include <cryptoTools/Network/BtEndpoint.h>
#include <cryptoTools/Network/BtSocket.h>

#include <stdio.h>
#include <algorithm>
#include <sstream>

namespace osuCrypto
{

    extern void split(const std::string &s, char delim, std::vector<std::string> &elems);
    extern std::vector<std::string> split(const std::string &s, char delim);

    BtIOService::BtIOService(u64 numThreads)
        :
        mIoService(),
        mWorker(new boost::asio::io_service::work(mIoService)),
        mStopped(false)
    {


        // Determine how many processors are on the system
        //SYSTEM_INFO SystemInfo;
        //GetSystemInfo(&SystemInfo);

        // if they provided 0, the use the number of processors worker threads
        numThreads = (numThreads) ? numThreads : std::thread::hardware_concurrency();
        mWorkerThrds.resize(numThreads);
        u64 i = 0;
        // Create worker threads based on the number of processors available on the
        // system. Create two worker threads for each processor
        for (auto& thrd : mWorkerThrds)
        {
            // Create a server worker thread and pass the completion port to the thread
            thrd = std::thread([&, i]()
            {
                setThreadName("io_Thrd_" + std::to_string(i));
                mIoService.run();

                //std::cout << "io_Thrd_" + std::to_string(i) << " closed" << std::endl;
            });
            ++i;
        }
    }

    BtIOService::~BtIOService()
    {
        // block until everything has shutdown.
        //stop();
    }

    void BtIOService::stop()
    {
        std::lock_guard<std::mutex> lock(mMtx);

        // Skip if its already shutdown.
        if (mStopped == false)
        {
            mWorker.reset(nullptr);
            mStopped = true;

            // tell all the acceptor threads to stop accepting new connections.
            for (auto& accptr : mAcceptors)
            {
                accptr.stop();
            }

            // delete all of their state.
            mAcceptors.clear();

            // wait for all the endpoints that use this IO service to finish.
            for (auto future : mEndpointStopFutures)
            {
                future.get();
            }

            // we can now join on them.
            for (auto& thrd : mWorkerThrds)
            {
                thrd.join();
            }

            // clean their state.
            mWorkerThrds.clear();
            // close the completion port since no more IO operations will be queued.

        }
    }

    void BtIOService::receiveOne(BtSocket* socket)
    {
        ////////////////////////////////////////////////////////////////////////////////
        //// THis is within the stand. We have sequential access to the recv queue. ////
        ////////////////////////////////////////////////////////////////////////////////

        BoostIOOperation& op = socket->mRecvQueue.front();

        if (op.mType == BoostIOOperation::Type::RecvData)
        {
            boost::asio::async_read(socket->mHandle,
                std::array<boost::asio::mutable_buffer, 1>{ op.mBuffs[0] },
                [&op, socket, this](const boost::system::error_code& ec, u64 bytesTransfered)
            {
                //////////////////////////////////////////////////////////////////////////
                //// This is *** NOT *** within the stand. Dont touch the recv queue! ////
                //////////////////////////////////////////////////////////////////////////


                if (bytesTransfered != boost::asio::buffer_size(op.mBuffs[0]) || ec)
                {
                    std::cout << ("rt error at " LOCATION "  ec=" + ec.message() + ". else bytesTransfered != " + std::to_string(boost::asio::buffer_size(op.mBuffs[0]))) << std::endl;
                    std::cout << "This could be from the other end closing too early or the connection beign dropped." << std::endl;
                    throw std::runtime_error("rt error at " LOCATION "  ec=" + ec.message() + ". else bytesTransfered != " + std::to_string(boost::asio::buffer_size(op.mBuffs[0])));
                }

                // We support two types of receives. One where we provide the expected size of the message and one
                // where we allow for variable length messages. op->other will be non null in the resize case and allow
                // us to resize the ChannelBuffer which will hold the data.
                if (op.mOther != nullptr)
                {
                    // Get the ChannelBuffer from the multi purpose other pointer.
                    ChannelBuffer* mH = (ChannelBuffer*)op.mOther;

                    // resize it. This could throw is the channel buffer chooses to.
                    mH->ChannelBufferResize(op.mSize);

                    // set the WSA buffer to point into the channel buffer storage location.
                    op.mBuffs[1] = boost::asio::buffer((char*)mH->ChannelBufferData(), op.mSize);
                }
                else
                {
                    // OK, this is the other type of recv where an expected size was provided.  op->mWSABufs[1].len
                    // will contain the expected size and op->mSize contains the size reported in the header.
                    if (boost::asio::buffer_size(op.mBuffs[1]) != op.mSize)
                    {
                        auto msg = "The provided buffer does not fit the received message. Expected: "
                            + std::to_string(boost::asio::buffer_size(op.mBuffs[1])) + ", actual: " + std::to_string(op.mSize);
                        std::cout << msg << std::endl;

                        std::unique_ptr<char[]> newBuff(nullptr);
                        auto e_ptr = std::make_exception_ptr(BadReceiveBufferSize(msg, op.mSize));

                        op.mException = std::current_exception();
                        op.mPromise->set_exception(op.mException);
                        delete op.mPromise;

                        return;
                    }
                }


                boost::asio::async_read(socket->mHandle,
                    std::array<boost::asio::mutable_buffer, 1>{ op.mBuffs[1] },
                    [&op, socket, this](const boost::system::error_code& ec, u64 bytesTransfered)
                {
                    //////////////////////////////////////////////////////////////////////////
                    //// This is *** NOT *** within the stand. Dont touch the recv queue! ////
                    //////////////////////////////////////////////////////////////////////////


                    if (bytesTransfered != boost::asio::buffer_size(op.mBuffs[1]) || ec)
                        throw std::runtime_error("Network error, other end may have crashed. Received incomplete message. error at " LOCATION);


                    socket->mTotalRecvData += boost::asio::buffer_size(op.mBuffs[1]);

                    // signal that the recv has completed.
                    if (op.mException)
                        op.mPromise->set_exception(op.mException);
                    else
                        op.mPromise->set_value();

                    delete op.mPromise;

                    socket->mRecvStrand.dispatch([socket, this]()
                    {
                        ////////////////////////////////////////////////////////////////////////////////
                        //// This is within the stand. We have sequential access to the recv queue. ////
                        ////////////////////////////////////////////////////////////////////////////////

                        socket->mRecvQueue.pop_front();

                        // is there more messages to recv?
                        bool sendMore = (socket->mRecvQueue.size() != 0);

                        if (sendMore)
                        {
                            receiveOne(socket);
                        }
                    });
                });


            });
        }
        else if (op.mType == BoostIOOperation::Type::CloseRecv)
        {
            auto prom = op.mPromise;
            socket->mRecvQueue.pop_front();
            prom->set_value();
        }
        else
        {
            throw std::runtime_error("rt error at " LOCATION);
        }
    }

    void BtIOService::sendOne(BtSocket* socket)
    {
        ////////////////////////////////////////////////////////////////////////////////
        //// This is within the stand. We have sequential access to the send queue. ////
        ////////////////////////////////////////////////////////////////////////////////

        BoostIOOperation& op = socket->mSendQueue.front();


        if (op.mType == BoostIOOperation::Type::SendData)
        {

            boost::asio::async_write(socket->mHandle, op.mBuffs, [&op, socket, this](boost::system::error_code ec, u64 bytesTransferred)
            {
                //////////////////////////////////////////////////////////////////////////
                //// This is *** NOT *** within the stand. Dont touch the send queue! ////
                //////////////////////////////////////////////////////////////////////////


                if (ec)
                {
                    std::cout << "network send error. " << ec.message() << std::endl;
                    throw std::runtime_error("rt error at " LOCATION);

                }

                // lets delete the other pointer as its either nullptr or a buffer that was allocated
                delete (ChannelBuffer*)op.mOther;

                // make sure all the data sent. If this fails, look up whether WSASend guarantees that all the data in the buffers will be send.
                if (bytesTransferred !=
                    boost::asio::buffer_size(op.mBuffs[0]) + boost::asio::buffer_size(op.mBuffs[1]))
                {
                    std::cout << "failed to send all data. Expected to send "
                        << (boost::asio::buffer_size(op.mBuffs[0]) + boost::asio::buffer_size(op.mBuffs[1]))
                        << "  but transfered " << bytesTransferred << std::endl;

                    throw std::runtime_error("rt error at " LOCATION);
                }

                socket->mOutstandingSendData -= op.mSize;

                // if this was a synchronous send, fulfill the promise that the message was sent.
                if (op.mPromise != nullptr)
                    op.mPromise->set_value();

                // if they provided a callback, execute it.
                if (op.mCallback)
                    op.mCallback();

                socket->mSendStrand.dispatch([socket, this]()
                {
                    ////////////////////////////////////////////////////////////////////////////////
                    //// This is within the stand. We have sequential access to the send queue. ////
                    ////////////////////////////////////////////////////////////////////////////////

                    socket->mSendQueue.pop_front();

                    // Do we have more messages to be sent?
                    auto sendMore = socket->mSendQueue.size();


                    if (sendMore)
                    {
                        sendOne(socket);
                    }
                });
            });

        }
        else if (op.mType == BoostIOOperation::Type::CloseSend)
        {
            // This is a special case which may happen if the channel calls stop()
            // with async sends still queued up, we will get here after they get completes. fulfill the
            // promise that all async send operations have been completed.
            auto prom = op.mPromise;
            socket->mSendQueue.pop_front();
            prom->set_value();
        }
        else
        {
            std::cout << "error" + boost::lexical_cast<std::string>(socket) << std::endl;
            throw std::runtime_error("rt error at " LOCATION);
        }
    }

    void BtIOService::dispatch(BtSocket* socket, BoostIOOperation& op)
    {
        switch (op.mType)
        {
        case BoostIOOperation::Type::RecvData:
        {

            if (op.mOther == nullptr &&  op.mSize == 0)
                throw std::runtime_error("rt error at " LOCATION);

        }
        case BoostIOOperation::Type::CloseRecv:
        {

            // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
            socket->mRecvStrand.post([this, socket, op]()
            {
                // the queue must be guarded from concurrent access, so add the op within the strand
                //socket->mTotalRecvData += op.mSize;

                // queue up the operation.
                socket->mRecvQueue.push_back(op);

                // check to see if we should kick off a new set of recv operations. If the size > 1, then there
                // is already a set of recv operations that will kick off the newly queued recv when its turn comes around.
                bool startRecving = (socket->mRecvQueue.size() == 1);


                if (startRecving)
                {
                    // ok, so there isn't any recv operations currently underway. Lets kick off the first one. Subsequent recvs
                    // will be kicked off at the completion of this operation.
                    receiveOne(socket);
                }
            });
        }
        break;
        case BoostIOOperation::Type::SendData:

            if (op.mSize == 0)
            {

                //std::cout << "\n\n" << Backtrace() << std::endl;
                throw std::runtime_error("Network error, tried to send zero sized messsage." LOCATION);
            }

        case BoostIOOperation::Type::CloseSend:
        {

            // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
            socket->mSendStrand.post([this, socket, op]()
            {
                // the queue must be guarded from concurrent access, so add the op within the strand

                // add the operation to the queue.
                socket->mSendQueue.push_back(op);

                socket->mTotalSentData += op.mSize;
                socket->mOutstandingSendData += op.mSize;
                socket->mMaxOutstandingSendData = std::max((u64)socket->mOutstandingSendData, (u64)socket->mMaxOutstandingSendData);

                // check to see if we should kick off a new set of send operations. If the size > 1, then there
                // is already a set of send operations that will kick off the newly queued send when its turn comes around.
                auto startSending = (socket->mSendQueue.size() == 1);

                if (startSending)
                {

                    // ok, so there isn't any send operations currently underway. Lets kick off the first one. Subsequent sends
                    // will be kicked off at the completion of this operation.
                    sendOne(socket);

                }
            });
        }
        break;
        default:

            throw std::runtime_error("unknown BoostIOOperation::Type");
            break;
        }
    }


    BtAcceptor* BtIOService::getAcceptor(BtEndpoint& endpoint)
    {

        if (endpoint.isHost())
        {
            std::lock_guard<std::mutex> lock(mMtx);

            // see if there already exists an acceptor that this endpoint can use.
            auto acceptorIter = std::find_if(
                mAcceptors.begin(),
                mAcceptors.end(), [&](const BtAcceptor& acptr)
            {
                return acptr.mPort == endpoint.port();
            });

            if (acceptorIter == mAcceptors.end())
            {
                // an acceptor does not exist for this port. Lets create one.
                mAcceptors.emplace_back(*this);
                auto& acceptor = mAcceptors.back();


                auto port = endpoint.port();
                auto ip = endpoint.IP();

                acceptor.bind(port, ip);

                acceptor.start();

                return &acceptor;
            }
            else
            {
                // there is an acceptor already accepting sockets on the desired port. So return it.
                return &(*acceptorIter);
            }
        }
        else
        {
            // client end points dont need acceptors since they initiate the connection.
            throw std::runtime_error("rt error at " LOCATION);
        }
    }


}
