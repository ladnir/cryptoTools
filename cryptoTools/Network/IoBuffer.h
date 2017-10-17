#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>

#include <future> 
#include <functional> 
#include <memory> 
#include <boost/asio.hpp>

namespace osuCrypto { 

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
        std::is_same<std::enable_if_t<
        std::is_convertible<
			typename Container::pointer,
            decltype(std::declval<Container>().data())>::value &&
        std::is_convertible<
			typename Container::size_type,
			decltype(std::declval<Container>().size())>::value &&
		std::is_pod<typename Container::value_type>::value &&
		std::is_pod<Container>::value == false>
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

        container.resize(size / sizeof(typename  T::value_type));
        return true;
    }


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
        std::array<boost::asio::mutable_buffer,2> mBuffs;
        std::promise<void> mPromise;
        std::function<void()> mCallback;



        virtual u8* data() const { return nullptr; };
        virtual u64 size() const { return 0; };
        virtual bool resize(u64) { return false; };
    };


    class PointerSizeBuff : public IOOperation {
    public:
        PointerSizeBuff() = delete;
        PointerSizeBuff(const void* data, u64 size, IOOperation::Type t)
            : IOOperation(t)
        {
            mBuffs[1] = boost::asio::buffer((void*)data, size);
        }

        u8* data() const override { return (u8*)boost::asio::buffer_cast<u8*>(mBuffs[1]); }
        u64 size() const override { return boost::asio::buffer_size(mBuffs[1]); }
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


    template <typename F>
    class MoveChannelBuff :public IOOperation {
    public:
        MoveChannelBuff() = delete;
        F mObj;
        MoveChannelBuff(F&& obj)
            : IOOperation(IOOperation::Type::SendData), mObj(std::move(obj))
        {
            mBuffs[1] = boost::asio::buffer(channelBuffData(mObj), channelBuffSize(mObj));
        }

        u8* data() const override { return channelBuffData(mObj); }
        u64 size() const override { return channelBuffSize(mObj); }
    };

    template <typename T>
    class MoveChannelBuff<std::unique_ptr<T>> :public IOOperation {
    public:
        MoveChannelBuff() = delete;
        typedef std::unique_ptr<T> F;
        F mObj;
        MoveChannelBuff(F&& obj)
            : IOOperation(IOOperation::Type::SendData), mObj(std::move(obj))
        {
            //mSize = u32( channelBuffSize(*mObj));
            mBuffs[1] = boost::asio::buffer(channelBuffData(*mObj), channelBuffSize(*mObj));
        }

        u8* data() const override { return channelBuffData(*mObj); }
        u64 size() const override { return channelBuffSize(*mObj); }
    };


    template <typename T>
    class  MoveChannelBuff<std::shared_ptr<T>> : public IOOperation {
    public:
        MoveChannelBuff() = delete;
        typedef std::shared_ptr<T> F;
        F mObj;
        MoveChannelBuff(F&& obj)
            : IOOperation(IOOperation::Type::SendData), mObj(std::move(obj))
        {
            //mSize = u32( channelBuffSize(*mObj));
            mBuffs[1] = boost::asio::buffer(channelBuffData(*mObj), channelBuffSize(*mObj));
        }

        u8* data() const override { return channelBuffData(*mObj); }
        u64 size() const override { return channelBuffSize(*mObj); }
    };

    template <typename F>
    class  ChannelBuffRef :public IOOperation {
    public:
        ChannelBuffRef() = delete;
        const F& mObj;
        ChannelBuffRef(const F& obj, IOOperation::Type t) : IOOperation(t), mObj(obj) {}

        u8* data() const override { return channelBuffData(mObj); }
        u64 size() const override { return channelBuffSize(mObj); }
    };

    template <typename F>
    class ResizableChannelBuffRef :public ChannelBuffRef<F> {
    public:
        ResizableChannelBuffRef() = delete;
        ResizableChannelBuffRef(F& obj) 
            : ChannelBuffRef<F>(obj, IOOperation::Type::RecvData)
        {}

        bool resize(u64 s) override { return channelBuffResize((F&)ChannelBuffRef<F>::mObj, s); }
    };



}
