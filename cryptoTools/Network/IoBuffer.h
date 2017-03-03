#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>


#include <deque>
#include <mutex>
#include <future> 
#include <functional> 
#include <memory> 

#include <cryptoTools/Network/IOService.h>

namespace osuCrypto { 

    class WinNetIOService;
    class ChannelBuffer;



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
    ///    * std::is_pod<Container>::value == true
    template<typename Container>
    using is_container =
        std::is_same<std::enable_if_t<
        std::is_convertible<typename Container::pointer,
        decltype(std::declval<Container>().data())>::value &&
        std::is_convertible<typename Container::size_type,
        decltype(std::declval<Container>().size())>::value &&
        std::is_pod<typename Container::value_type>::value>
        ,
        void>;
    

    template<typename T>
    inline u8* channelBuffData(const T& container)
    {
        return (u8*)container.data();
    }

    template<typename T>
    inline u64 channelBuffSize(const T& container)
    {
        return container.size() * sizeof(typename  T::value_type);
    }

    template<typename T>
    inline bool channelBuffResize(T& container, u64 size)
    {
        if (size % sizeof(typename  T::value_type)) return false;

        container.resize(size / sizeof(typename  T::value_type));
        return true;
    }


    struct ChannelBuffBase
    {
        virtual u8* data() const = 0;
        virtual u64 size() const = 0;
        virtual bool resize(u64) { return false; };
        virtual ~ChannelBuffBase() {}
    };

    template <typename F>
    struct MoveChannelBuff : ChannelBuffBase {
        F mObj;
        MoveChannelBuff(F&& obj) : mObj(std::move(obj)) {}

        u8* data() const override { return channelBuffData(mObj); }
        u64 size() const override { return channelBuffSize(mObj); }
    };


    template <typename T>
    struct MoveChannelBuff<std::unique_ptr<T>> : ChannelBuffBase {

        typedef std::unique_ptr<T> F;
        F mObj;
        MoveChannelBuff(F&& obj) : mObj(std::move(obj)) {}

        u8* data() const override { return channelBuffData(*mObj); }
        u64 size() const override { return channelBuffSize(*mObj); }
    };
    

    template <typename T>
    struct MoveChannelBuff<std::shared_ptr<T>> : ChannelBuffBase {

        typedef std::shared_ptr<T> F;
        F mObj;
        MoveChannelBuff(F&& obj) : mObj(std::move(obj)) {}

        u8* data() const override { return channelBuffData(*mObj); }
        u64 size() const override { return channelBuffSize(*mObj); }
    };

    template <typename F>
    struct ChannelBuffRef : ChannelBuffBase {
        const F& mObj;
        ChannelBuffRef(const F& obj) : mObj(obj) {}

        u8* data() const override { return channelBuffData(mObj); }
        u64 size() const override { return channelBuffSize(mObj); }
    };

    template <typename F>
    struct ResizableChannelBuffRef : ChannelBuffRef<F> {
        ResizableChannelBuffRef(F& obj) 
            : 
            ChannelBuffRef<F>(obj)
        {}

        bool resize(u64 s) override { return channelBuffResize((F&)ChannelBuffRef<F>::mObj, s); }
    };



    struct IOOperation
    {
        enum class Type
        {
            RecvName,
            RecvData,
            CloseRecv,
            SendData,
            CloseSend,
            CloseThread
        };

        IOOperation()
        {
            clear();
        }

        IOOperation(const IOOperation& copy) = default;
        IOOperation(IOOperation&& copy) = default;
        //    :
        //    mMode(copy.mMode);
        //    mSize = copy.mSize;
        //    mBuffs[0] = boost::asio::buffer(&mSize, sizeof(u32));
        //    mBuffs[1] = copy.mBuffs[1];
        //    mContainer = std::move(copy.mContainer);
        //    mPromise = std::move(copy.mPromise);
        //{
        //}

        void clear()
        {
            mType = (Type)0;
            mSize = 0; 
            mBuffs[0] = boost::asio::buffer(&mSize, sizeof(u32));
            mBuffs[1] = boost::asio::mutable_buffer();
            mContainer = nullptr;
            mPromise = nullptr;
        } 


        std::array<boost::asio::mutable_buffer,2> mBuffs;
        Type mType;
        u32 mSize;

        ChannelBuffBase* mContainer;
        std::promise<u64>* mPromise;
        std::function<void()> mCallback;
    };



    //class Socket
    //{
    //public:
    //    Socket(IOService& ios);

    //    boost::asio::ip::tcp::socket mHandle;
    //    boost::asio::strand mSendStrand, mRecvStrand;

    //    std::deque<IOOperation> mSendQueue, mRecvQueue;
    //    bool mStopped;

    //    std::atomic<u64> mOutstandingSendData, mMaxOutstandingSendData, mTotalSentData, mTotalRecvData;
    //};

    //inline Socket::Socket(IOService& ios) :
    //    mHandle(ios.mIoService),
    //    mSendStrand(ios.mIoService),
    //    mRecvStrand(ios.mIoService),
    //    mStopped(false),
    //    mOutstandingSendData(0),
    //    mMaxOutstandingSendData(0),
    //    mTotalSentData(0),
    //    mTotalRecvData(0)
    //{}


}
