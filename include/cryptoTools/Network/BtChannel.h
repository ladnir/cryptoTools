#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/BtSocket.h>
#include <cryptoTools/Network/BtEndpoint.h>
#include <future>

namespace osuCrypto {





    class BtSocket;
    class BtEndpoint;
    class Endpoint;

    class Channel
    {

    public:

        Channel(BtEndpoint& endpoint, std::string localName, std::string remoteName);

        ~Channel();

        /// <summary>Get the local endpoint for this channel.</summary>
        Endpoint& getEndpoint();

        /// <summary>The handle for this channel. Both ends will always have the same name.</summary>
        std::string getName() const;

        /// <summary>Returns the name of the remote endpoint.</summary>
        std::string getRemoteName() const;

        /// <summary>Sets the data send and recieved counters to zero.</summary>
        void resetStats();

        /// <summary>Returns the amount of data that this channel has sent since it was created or when resetStats() was last called.</summary>
        u64 getTotalDataSent() const;

        /// <summary>Returns the amount of data that this channel has sent since it was created or when resetStats() was last called.</summary>
        u64 getTotalDataRecv() const;

        /// <summary>Returns the maximum amount of data that this channel has queued up to send since it was created or when resetStats() was last called.</summary>
        u64 getMaxOutstandingSendData() const;

        /// <summary>length bytes starting at data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
        void asyncSend(const void * data, u64 length);

        /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
        void asyncSend(const void * bufferPtr, u64 length, std::function<void()> callback);

        /// <summary>buffer will be MOVED and then sent over the network asynchronously.
        /// Note: The type within the unique_ptr must be a container type, see is_container for requirements.
        /// Returns: void </summary>
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSend(std::unique_ptr<Container> buffer);

        /// <summary>buffer will be MOVED and then sent over the network asynchronously.
        /// Note: The type within the unique_ptr must be a container type, see is_container for requirements.
        /// Returns: void </summary>
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSend(std::shared_ptr<Container> buffer);


        /// <summary>Container c will be MOVED and then sent over the network asynchronously.
        /// Note: The type of Container must be a container type, see is_container for requirements.
        /// Returns: void </summary>
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSend(Container&& c);

        /// <summary>Performs a data copy and then sends the result over the network asynchronously.
        /// Note: The type of Container must be a container type, see is_container for requirements.
        /// Returns: void </summary>
        template <typename  Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSendCopy(const Container& buf);

        /// <summary>Performs a data copy and then sends the result over the network asynchronously. </summary>
        void asyncSendCopy(const void * bufferPtr, u64 length);

        /// <summary>Synchronous call to send length bytes starting at data over the network. </summary>
        void send(const void * bufferPtr, u64 length);

        /// <summary> Synchronous call to send the data in Container over the network.
        /// Note: The type of Container must be a container type, see is_container for requirements.
        /// Returns: void  </summary>
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            send(const Container& buf);

        /// <summary>Asynchronous call to recv length bytes of data over the network. The data will be written at dest.
        /// WARNING: return value will through if received message length does not match.
        /// Returns: a void future that is fulfilled when all of the data has been written. </summary>
        std::future<void> asyncRecv(void* dest, u64 length);

        /// <summary>Asynchronous call to receive data over the network.
        /// Note: Conatiner can be resizable. If received size does not match Container::size(),
        ///       Container::resize(Container::size_type newSize) will be called if avaliable.
        /// Returns: a void future that is fulfilled when all of the data has been written. </summary>
        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            !has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
            asyncRecv(Container& c);


        /// <summary>Asynchronous call to receive data over the network.
        /// Note: Conatiner can be resizable. If received size does not match Container::size(),
        ///       Container::resize(Container::size_type newSize) will be called if avaliable.
        /// Returns: a void future that is fulfilled when all of the data has been written. </summary>
        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
            asyncRecv(Container& c);

        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            has_resize<Container, void(typename Container::size_type)>::value, void>
            recv(Container & c)
        {
                asyncRecv(c).get();
        }

        //template <class Container>
        //typename std::enable_if_t<
        //    is_container<Container>::value &&
        //    !is_resizable_container<Container>::value, void>
        //    Channel::recv(Container & c);
        //has_resize<Container, void(typename Container::size_type)>::value

        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            !has_resize<Container, void(typename Container::size_type)>::value, void>
            recv(Container & c)
        {
            asyncRecv(c).get();
        }

        /// <summary>Synchronous call to receive data over the network.
        /// WARNING: will through if received message length does not match.</summary>
        void recv(void * dest, u64 length);

        /// <summary>Returns whether this channel is open in that it can send/receive data</summary>
        bool opened();

        /// <summary>A blocking call that waits until the channel is open in that it can send/receive data</summary>
        void waitForOpen();

        /// <summary>Close this channel to denote that no more data will be sent or received.</summary>
        void close();


        std::unique_ptr<BtSocket> mSocket;
        BtEndpoint& mEndpoint;
        std::string mRemoteName, mLocalName;

    private:
        void dispatch(BoostIOOperation& op);
    };

    typedef Channel BtChannel;



    template<class Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSend(std::unique_ptr<Container> c)
    {
        //asyncSend(std::move(*mH));
        if (mSocket->mStopped || c->size() > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;
        op.mContainer = (new MoveChannelBuff<std::unique_ptr<Container>>(std::move(c)));

        op.mSize = u32(op.mContainer->size());
        op.mBuffs[1] = boost::asio::buffer(op.mContainer->data(), op.mContainer->size());

        op.mType = BoostIOOperation::Type::SendData;

        dispatch(op);
    }

    template<class Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSend(std::shared_ptr<Container> c)
    {
        //asyncSend(std::move(*mH));
        if (mSocket->mStopped || c->size() > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;
        op.mContainer = (new MoveChannelBuff<std::shared_ptr<Container>>(std::move(c)));

        op.mSize = u32(op.mContainer->size());
        op.mBuffs[1] = boost::asio::buffer(op.mContainer->data(), op.mContainer->size());

        op.mType = BoostIOOperation::Type::SendData;

        dispatch(op);
    }


    template<class Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSend(Container && c)
    {
        if (mSocket->mStopped || c.size() > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;
        op.mContainer = (new MoveChannelBuff<Container>(std::move(c)));

        op.mSize = u32(op.mContainer->size());
        op.mBuffs[1] = boost::asio::buffer(op.mContainer->data(), op.mContainer->size());

        op.mType = BoostIOOperation::Type::SendData;

        dispatch(op);
    }

    template <class Container>
    typename std::enable_if_t<
        is_container<Container>::value &&
        !has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
        Channel::asyncRecv(Container & c)
    {
        if (mSocket->mStopped)
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;
        op.clear();


        op.mType = BoostIOOperation::Type::RecvData;

        //op.mContainer = (new RefChannelBuff<Container>(c));
        op.mContainer = nullptr;

        op.mSize = c.size();
        op.mBuffs[1] = boost::asio::buffer(c.data(), c.size() * sizeof(typename Container::value_type));
        op.mPromise = new std::promise<void>();
        auto future = op.mPromise->get_future();

        dispatch(op);

        return future;
    }



    template <class Container>
    typename std::enable_if_t<
        is_container<Container>::value &&
        has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
        Channel::asyncRecv(Container & c)
    {
        if (mSocket->mStopped)
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;
        op.clear();


        op.mType = BoostIOOperation::Type::RecvData;

        op.mContainer = (new RefChannelBuff<Container>(c));
        //op.mContainer = nullptr;//

        op.mPromise = new std::promise<void>();
        auto future = op.mPromise->get_future();

        dispatch(op);

        return future;
    }

    //template <class Container>
    //typename std::enable_if_t<
    //    is_resizable_container<Container>::value, void>
    //    Channel::recv(Container & c)
    //{
    //    asyncRecv(c).get();
    //}

    //template <class Container>
    //typename std::enable_if_t<
    //    is_container<Container>::value &&
    //    !is_resizable_container<Container>::value, void>
    //    Channel::recv(Container & c)
    //{
    //    asyncRecv(c).get();
    //}

    template<class Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::send(const Container & buf)
    {
        send((u8*)buf.data(), buf.size() * sizeof(typename Container::value_type));
    }

    template<typename Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSendCopy(const Container & buf)
    {
        asyncSend(std::move(Container(buf)));
    }
}
