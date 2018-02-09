#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>

#include <future> 
#include <functional> 
#include <memory> 
#include <boost/asio.hpp>

namespace osuCrypto {

    using error_code = boost::system::error_code;
    using io_completion_handle = std::function<void(error_code, u64)>;

    template<typename, typename T>
    struct has_resize {
        static_assert(
            std::integral_constant<T, false>::value,
            "Second template parameter needs to be of function type.");
    };

    // specialization that does the checking
    template<typename C, typename Ret, typename... Args>
    struct has_resize<C, Ret(Args...)> {
    private:
        template<typename T>
        static constexpr auto check(T*)
            -> typename
            std::is_same<
            decltype(std::declval<T>().resize(std::declval<Args>()...)),
            Ret    // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            >::type;  // attempt to call it and see if the return type is correct

        template<typename>
        static constexpr std::false_type check(...);

        typedef decltype(check<C>(0)) type;

    public:
        static constexpr bool value = type::value;
    };


    /// type trait that defines what is considered a STL like Container
    /// 
    /// Must have the following member types:  pointer, size_type, value_type
    /// Must have the following member functions:
    ///    * Container::pointer Container::data();
    ///    * Container::size_type Container::size();
    /// Must contain Plain Old Data:
    ///    * std::is_pod<Container::value_type>::value == true
    template<typename Container>
    using is_container =
        std::is_same<typename std::enable_if<
        std::is_convertible<
        typename Container::pointer,
        decltype(std::declval<Container>().data())>::value &&
        std::is_convertible<
        typename Container::size_type,
        decltype(std::declval<Container>().size())>::value &&
        std::is_pod<typename Container::value_type>::value &&
        std::is_pod<Container>::value == false>::type
        ,
        void>;

    template<typename T>
    inline u8* channelBuffData(const T& container) { return (u8*)container.data(); }

    template<typename T>
    inline u64 channelBuffSize(const T& container) { return container.size() * sizeof(typename  T::value_type); }

    template<typename T>
    inline bool channelBuffResize(T& container, u64 size)
    {
        if (size % sizeof(typename  T::value_type)) return false;

        try {
            container.resize(size / sizeof(typename  T::value_type));
        }
        catch (...)
        {
            return false;
        }
        return true;
    }


    class IOOperation2
    {
    public:
        using size_header_type = u32;

        IOOperation2() = default;
        IOOperation2(const IOOperation2& copy) = delete;
        IOOperation2(IOOperation2&& copy) = delete;

        u32 mIdx;

        virtual void async_perform(ChannelBase* base, io_completion_handle completionHandle) = 0;

        // todo, make this an error code.
        virtual void cancel(std::string reason) = 0;
    };

    // A class for sending or receiving data over a channel. 
    // Data sent/received with this type sent over the network 
    // with a header denoting its size in bytes.
    class SizedPointerBuff : public IOOperation2
    {
    public:
        SizedPointerBuff() = default;

        SizedPointerBuff(const u8* data, u64 size)
            : mSize(size)
            , mBuffs{ {
                boost::asio::buffer((void*)&mSize, sizeof(size_header_type)) ,
                boost::asio::buffer((void*)data, size) } }
        { }

        void set(const u8* data, u64 size)
        {
            mSize = size;
            mBuffs[0] = boost::asio::buffer((void*)&mSize, sizeof(size_header_type));
            mBuffs[1] = boost::asio::buffer((void*)data, size);
        }

        size_header_type mSize;
        std::array<boost::asio::mutable_buffer, 2> mBuffs;
    };



    class SizedPointerSendBuff : public SizedPointerBuff
    {
        SizedPointerSendBuff(const u8* data, u64 size)
            : SizedPointerBuff(data, size)
        {}

        io_completion_handle mComHandle;
        void async_perform(ChannelBase* base, io_completion_handle completionHandle) override
        {
            mComHandle = std::move(completionHandle);
            base->async_Send(mBuffs, [this](error_code ec, u64 bytesTransferred) {

                auto expSize = boost::asio::buffer_size(mBuffs[0]) + boost::asio::buffer_size(mBuffs[1]);

                // make sure all the data sent. If this fails, look up whether WSASend guarantees that all the data in the buffers will be send.
                if (bytesTransferred != expSize && !ec)
                {
                    auto reason = std::string("failed to send all data. Expected to send ")
                        + ToString(expSize)
                        + " bytes but transfered " + ToString(bytesTransferred) + "\n"
                        + "  at  " + LOCATION;

                    std::cout << reason << std::endl;
                    TODO("implement custom error code and add the reason there");
                    ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
                }

                mComHandle(ec, bytesTransferred);
            });
        }

        void cancel(std::string _) override {};
    };



    class SizedPointerSendBuff : public SizedPointerBuff
    {
        SizedPointerSendBuff(const u8* data, u64 size)
            : SizedPointerBuff(data, size)
        {}

        io_completion_handle mComHandle;
        void async_perform(ChannelBase* base, io_completion_handle completionHandle) override
        {
            mComHandle = std::move(completionHandle);
            base->async_Send(mBuffs, [this](error_code ec, u64 bytesTransferred) {

                auto expSize = boost::asio::buffer_size(mBuffs[0]) + boost::asio::buffer_size(mBuffs[1]);

                // make sure all the data sent. If this fails, look up whether WSASend guarantees that all the data in the buffers will be send.
                if (bytesTransferred != expSize && !ec)
                {
                    auto reason = std::string("failed to send all data. Expected to send ")
                        + ToString(expSize)
                        + " bytes but transfered " + ToString(bytesTransferred) + "\n"
                        + "  at  " + LOCATION;

                    std::cout << reason << std::endl;
                    TODO("implement custom error code and add the reason there");
                    ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
                }

                mComHandle(ec, bytesTransferred);
            });
        }

        void cancel(std::string _) override {};
    };



    template <typename F>
    class MoveChannelBuff : public SizedPointerSendBuff {
    public:
        MoveChannelBuff() = delete;
        F mObj;

        MoveChannelBuff(F&& obj)
            : mObj(std::move(obj))
        {   // set must be called after the move in case channelBuffData(mObj) != channelBuffData(obj)
            set(channelBuffData(mObj), channelBuffSize(mObj));
        }
    };


    template <typename T>
    class MoveChannelBuff<std::unique_ptr<T>> :public SizedPointerSendBuff {
    public:
        MoveChannelBuff() = delete;
        typedef std::unique_ptr<T> F;
        F mObj;
        MoveChannelBuff(F&& obj)
            : SizedPointerSendBuff(channelBuffData(*obj), channelBuffSize(*obj))
            , mObj(std::move(obj))
        {}
    };

    template <typename T>
    class MoveChannelBuff<std::shared_ptr<T>> :public SizedPointerSendBuff {
    public:
        MoveChannelBuff() = delete;
        typedef std::shared_ptr<T> F;
        F mObj;
        MoveChannelBuff(F&& obj)
            : SizedPointerSendBuff(channelBuffData(*obj), channelBuffSize(*obj))
            , mObj(std::move(obj))
        {}
    };


    template <typename F>
    class  FixedSizeChannelSendBuffRef :public SizedPointerSendBuff {
    public:
        const F& mObj;
        FixedSizeChannelSendBuffRef(const F& obj)
            : mObj(obj)
        {   // set must be called after the move in case channelBuffData(mObj) != channelBuffData(obj)
            set(channelBuffData(mObj), channelBuffSize(mObj));
        }
    };


    template <typename F>
    class  FixedSizeChannelRecvBuffRef :public SizedPointerRecvBuff {
    public:
        const F& mObj;
        FixedSizeChannelRecvBuffRef(const F& obj)
            : mObj(obj)
        {   // set must be called after the move in case channelBuffData(mObj) != channelBuffData(obj)
            set(channelBuffData(mObj), channelBuffSize(mObj));
        }
    };


    template <typename F>
    class ResizableChannelBuffRef :public IOOperation2 {
    public:
        ResizableChannelBuffRef() = delete;
        F& mObj;
        io_completion_handle mHandle;

        ResizableChannelBuffRef(F& obj)
            :mObj(obj)
        {}

        void async_perform(ChannelBase* base, io_completion_handle handle)
        {
            mHandle = std::move(handle);
            base->async_
        }

    };










    class BadReceiveBufferSize : public std::runtime_error
    {
    public:
        //std::string mWhat;
        u64 mSize;
        std::function<void(u8*)> mRescheduler;

        BadReceiveBufferSize(const std::string& what, u64 length, std::function<void(u8*)> rescheduler)
            :
            std::runtime_error(what),
            mSize(length),
            mRescheduler(std::move(rescheduler))
        { }

        BadReceiveBufferSize(const BadReceiveBufferSize& src) = default;
        BadReceiveBufferSize(BadReceiveBufferSize&& src) = default;
    };



    class IOOperation
    {

        IOOperation(const IOOperation& copy) = delete;
        IOOperation(IOOperation&& copy) = delete;

    public:

        enum class Type
        {
            RecvName,
            RecvData,
            CloseRecv,
            SendData,
            CloseSend,
            CloseThread
        };

        IOOperation(IOOperation::Type t)
        {
            mType = t;
            mIdx = 0;
        }

        virtual ~IOOperation() {}

    private:
        Type mType;
    public:
        const Type& type()const { return mType; }

        u32 mIdx;
        std::array<boost::asio::mutable_buffer, 2> mBuffs;
        std::promise<void> mPromise;
        std::function<void()> mCallback;



        virtual u8* data() const { return nullptr; };
        virtual u64 size() const { return 0; };
        virtual bool resize(u64) { return false; };
    };


    //class PointerSizeBuff : public IOOperation {
    //public:
    //    PointerSizeBuff() = delete;
    //    PointerSizeBuff(const void* data, u64 size, IOOperation::Type t)
    //        : IOOperation(t)
    //    {
    //        mBuffs[1] = boost::asio::buffer((void*)data, size);
    //    }

    //    u8* data() const override { return (u8*)boost::asio::buffer_cast<u8*>(mBuffs[1]); }
    //    u64 size() const override { return boost::asio::buffer_size(mBuffs[1]); }
    //};


    //template <typename F>
    //class MoveChannelBuff :public IOOperation {
    //public:
    //    MoveChannelBuff() = delete;
    //    F mObj;
    //    MoveChannelBuff(F&& obj)
    //        : IOOperation(IOOperation::Type::SendData), mObj(std::move(obj))
    //    {
    //        mBuffs[1] = boost::asio::buffer(channelBuffData(mObj), channelBuffSize(mObj));
    //    }

    //    u8* data() const override { return channelBuffData(mObj); }
    //    u64 size() const override { return channelBuffSize(mObj); }
    //};
    //template <typename T>
    //class  MoveChannelBuff<std::shared_ptr<T>> : public IOOperation {
    //public:
    //    MoveChannelBuff() = delete;
    //    typedef std::shared_ptr<T> F;
    //    F mObj;
    //    MoveChannelBuff(F&& obj)
    //        : IOOperation(IOOperation::Type::SendData), mObj(std::move(obj))
    //    {
    //        //mSize = u32( channelBuffSize(*mObj));
    //        mBuffs[1] = boost::asio::buffer(channelBuffData(*mObj), channelBuffSize(*mObj));
    //    }

    //    u8* data() const override { return channelBuffData(*mObj); }
    //    u64 size() const override { return channelBuffSize(*mObj); }
    //};



    // A class template that allows fewer than the specified number of bytes to be received. 
    template<typename T>
    class ReceiveAtMost
    {
    public:
        using pointer = T * ;
        using value_type = T;
        using size_type = u64;

        T* mData;
        u64 mMaxReceiveSize, mTrueReceiveSize;


        // A constructor that takes the loction to be written to and 
        // the maximum number of T's that should be written. 
        // Call 
        ReceiveAtMost(T* dest, u64 maxReceiveCount)
            : mData(dest)
            , mMaxReceiveSize(maxReceiveCount)
            , mTrueReceiveSize(0)
        {}


        u64 size() const
        {
            if (mTrueReceiveSize)
                return mTrueReceiveSize;
            else
                return mMaxReceiveSize;
        }

        const T* data() const { return mData; }
        T* data() { return mData; }

        void resize(u64 size)
        {
            if (size > mMaxReceiveSize) throw std::runtime_error(LOCATION);
            mTrueReceiveSize = size;
        }

        u64 receivedSize() const
        {
            return mTrueReceiveSize;
        }
    };



    //static_assert(std::is_convertible<
    //    typename ReceiveAtMost<u8>::pointer,
    //    decltype(std::declval<ReceiveAtMost<u8>>().data())>::value, "sss");
    //static_assert(std::is_convertible<
    //    typename ReceiveAtMost<u8>::size_type,
    //    decltype(std::declval<ReceiveAtMost<u8>>().size())>::value, "sss");
    //static_assert(std::is_pod<typename ReceiveAtMost<u8>::value_type>::value, "sss");
    //static_assert(std::is_pod<ReceiveAtMost<u8>>::value == false, "sss");
    static_assert(is_container<ReceiveAtMost<u8>>::value, "sss");
    static_assert(has_resize<ReceiveAtMost<u8>, void(typename ReceiveAtMost<u8>::size_type)>::value, "sss");


}
