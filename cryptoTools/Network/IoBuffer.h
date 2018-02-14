#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>

#include <string> 
#include <future> 
#include <functional> 
#include <memory> 
#include <boost/asio.hpp>
#include <system_error>
#include  <type_traits>;
#define CHANNEL_LOGGING

namespace osuCrypto {
    using error_code = boost::system::error_code;
    class ChannelBase;
    using io_completion_handle = std::function<void(const error_code&, u64)>;

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
    static_assert(is_container<ReceiveAtMost<u8>>::value, "sss");
    static_assert(has_resize<ReceiveAtMost<u8>, void(typename ReceiveAtMost<u8>::size_type)>::value, "sss");

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

    class CanceledOperation : public std::runtime_error
    {
    public:
        CanceledOperation(const std::string& str)
            : std::runtime_error(str)
        {}
    };


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

    template<typename T>
    class SpscQueue
    {
    public:

        struct BaseQueue
        {
            BaseQueue() = delete;
            BaseQueue(const BaseQueue&) = delete;
            BaseQueue(BaseQueue&&) = delete;

            BaseQueue(u64 cap)
                : mPopIdx(0)
                , mPushIdx(0)
                , mCapacity(cap)
                , mStorage(new T[cap])
            {};


            std::atomic<u64> mPopIdx;
            std::atomic<u64> mPushIdx;
            u64 mCapacity;
            std::unique_ptr<T[]> mStorage;

            u64 capacity() const { return mCapacity; }
            u64 size() const { return mPushIdx.load(std::memory_order_relaxed) - mPopIdx.load(std::memory_order_relaxed); }
            bool isFull() const { return size() == capacity(); }
            bool isEmpty() const { return size() == 0; }

            void push_back(T&& v)
            {
                if (isFull())
                    throw std::runtime_error("Queue is full " LOCATION);

                auto pushIdx = mPushIdx.load(std::memory_order_relaxed) % capacity();
                new (mStorage.get() + pushIdx) T(std::move(v));

                mPushIdx.fetch_add(1, std::memory_order::memory_order_release);
            }

            T& front()
            {
                if (isEmpty())
                    throw std::runtime_error("queue is empty. " LOCATION);

                auto popIdx = mPopIdx.load(std::memory_order_acquire) % capacity();
                return mStorage[popIdx];
            }

            void pop_front()
            {
                if (isEmpty())
                    throw std::runtime_error("queue is empty. " LOCATION);

                auto popIdx = mPopIdx.load(std::memory_order::memory_order_relaxed);
                mStorage[popIdx % capacity()].~T();
                mPopIdx.fetch_add(1, std::memory_order::memory_order_relaxed);
            }
        };

        std::list<BaseQueue> mQueues;

        SpscQueue(u64 cap = 64)
        {
            mQueues.emplace_back(cap);
        }

        u64 capacity() const { return mQueues.back().capacity(); }
        u64 size() const { return mQueues.back().size(); }
        bool isFull() const { return mQueues.back().isFull(); }
        bool isEmpty() const { return mQueues.front().isEmpty(); }

        void push_back(T&& v)
        {
            mQueues.back().push_back(std::move(v));
        }

        T& front()
        {
            return mQueues.front().front();
        }

        void pop_front()
        {
            mQueues.front().pop_front();

            if (mQueues.front().size() == 0 && mQueues.size() > 1)
                mQueues.pop_front();
        }

        void unsafeReserve(u64 newSize)
        {
            mQueues.emplace_back(newSize);
        }
    };


    template<typename T, int StorageSize = 24 /* makes the whole thing 32 bytes */>
    class SBO_ptr
    {
    public:
        using base_type = T;
        using Storage = typename std::aligned_storage<StorageSize>::type;


        T* mData = nullptr;
        Storage mStorage;

        SBO_ptr() = default;
        SBO_ptr(const SBO_ptr<T>&) = delete;

        SBO_ptr(SBO_ptr<T>&& m)
        {
            if (m.isSBO())
            {
                // will perform the placement new move constructor using the
                // derived type constructor.
                Interface& i = m.getInterface();
                getInterface().moveConstruct(std::move(i));
                mData = (T*)&getInterface();
            }
            else
            {
                std::swap(mData, m.mData);
            }
        }

        ~SBO_ptr()
        {
            destruct();
        }


        template<typename U, typename... Args >
        typename std::enable_if<
            (sizeof(U) <= sizeof(Storage)) &&
            std::is_base_of<T, U>::value &&
            std::is_constructible<U, Args...>::value
        >::type
            New(Args&&... args)
        {
            destruct();

            // Do a placement new to the local storage and then take the
            // address of the U type and store that in our data pointer.
            mData = &(new (&getInterface()) Impl<U>(args...))->mU;
        }

        template<typename U, typename... Args >
        typename std::enable_if<
            (sizeof(U) > sizeof(Storage)) &&
            std::is_base_of<T, U>::value &&
            std::is_constructible<U, Args...>::value
                >::type
            New(Args&&... args)
        {
            destruct();

            // this object is too big, use the allocator. Local storage
            // will be unused as denoted by (isSBO() == false).
            mData = new U(std::forward<Args>(args)...);
        }


        bool isSBO() const { return data() == (T*)&getInterface(); }

        T* operator->() { return data(); }
        T* data() { return mData; }

        const T* operator->() const { return data(); }
        const T* data() const  { return mData; }


    private:

        void destruct()
        {
            if (isSBO())
                // manually call the virtual destructor.
                getInterface().~Interface();
            else
                // let the compiler call the destructor
                delete data();
        }


        struct Interface
        {
            virtual ~Interface() {};
            // assumes object is uninitialized.
            virtual void moveConstruct(Interface&& rhs) = 0;
        };

        template<typename U>
        struct Impl : Interface
        {
            virtual void moveConstruct(Interface&& rhs) {
                new (&mU) U(std::move(static_cast<Impl<U>>(rhs).mU));
            }
            U mU;
        };


        Interface& getInterface()
        {
            return *(Interface*)&mStorage;
        }

        const Interface& getInterface() const
        {
            return *(Interface*)&mStorage;
        }
    };


    template<typename T, typename U, typename... Args>
    typename  std::enable_if<
        std::is_constructible<U, Args...>::value &&
        std::is_base_of<T, U>::value, SBO_ptr<T>>::type
        make_SBO_ptr(Args&&... args)
    {
        SBO_ptr<T> t;
        t.New(std::forward<Args>(args)...);
        return std::move(t);
    }


    namespace details
    {


        class SendOperation
        {
        public:
            SendOperation() = default;
            SendOperation(const SendOperation& copy) = delete;
            SendOperation(SendOperation&& copy) = delete;

            virtual void asyncPerform(ChannelBase* base, io_completion_handle completionHandle) = 0;
            virtual void cancel(std::string reason) = 0;
            virtual std::string toString() const;

#ifdef CHANNEL_LOGGING
            u64 mIdx;
#endif
        };

        class RecvOperation
        {
        public:
            RecvOperation() = default;
            RecvOperation(const RecvOperation& copy) = delete;
            RecvOperation(RecvOperation&& copy) = delete;

            virtual void asyncPerform(ChannelBase* base, io_completion_handle completionHandle) = 0;
            virtual void cancel(std::string reason) = 0;
            virtual std::string toString() const;

#ifdef CHANNEL_LOGGING
            u64 mIdx;
#endif
        };


        // A class for sending or receiving data over a channel. 
        // Data sent/received with this type sent over the network 
        // with a header denoting its size in bytes.
        class BasicSizedBuff
        {
        public:
            using size_header_type = u32;

            BasicSizedBuff()
            {
                mBuffs[0] = boost::asio::buffer((void*)&mHeaderSize, sizeof(size_header_type));
            };

            BasicSizedBuff(const u8* data, u64 size)
                : mHeaderSize(size)
                , mBuffs{ {
                    boost::asio::buffer((void*)&mHeaderSize, sizeof(size_header_type)) ,
                    boost::asio::buffer((void*)data, size) } }
            {
                Expects(size < std::numeric_limits<size_header_type>::max());
            }

            void set(const u8* data, u64 size)
            {
                Expects(size < std::numeric_limits<size_header_type>::max());
                mHeaderSize = size;
                mBuffs[0] = boost::asio::buffer((void*)&mHeaderSize, sizeof(size_header_type));
                mBuffs[1] = boost::asio::buffer((void*)data, size);
            }

            inline u64 getHeaderSize() const { return mHeaderSize; }
            inline u64 getBufferSize() const { return boost::asio::buffer_size(mBuffs[1]); }

            size_header_type mHeaderSize;
            std::array<boost::asio::mutable_buffer, 2> mBuffs;
        };




        class FixedSendBuff : public BasicSizedBuff, public SendOperation
        {
        public:
            FixedSendBuff() = default;
            FixedSendBuff(const u8* data, u64 size)
                : BasicSizedBuff(data, size)
            {}

            void asyncPerform(ChannelBase* base, io_completion_handle completionHandle) override;
            void cancel(std::string _) override {};

            std::string toString() const override;
        };

        template <typename F>
        class MoveSendBuff : public FixedSendBuff {
        public:
            MoveSendBuff() = delete;
            F mObj;

            MoveSendBuff(F&& obj)
                : mObj(std::move(obj))
            {   // set must be called after the move in case channelBuffData(mObj) != channelBuffData(obj)
                set(channelBuffData(mObj), channelBuffSize(mObj));
            }
        };

        template <typename T>
        class MoveSendBuff<std::unique_ptr<T>> :public FixedSendBuff {
        public:
            MoveSendBuff() = delete;
            typedef std::unique_ptr<T> F;
            F mObj;
            MoveSendBuff(F&& obj)
                : FixedSendBuff(channelBuffData(*obj), channelBuffSize(*obj))
                , mObj(std::move(obj))
            {}
        };

        template <typename T>
        class MoveSendBuff<std::shared_ptr<T>> :public FixedSendBuff {
        public:
            MoveSendBuff() = delete;
            typedef std::shared_ptr<T> F;
            F mObj;
            MoveSendBuff(F&& obj)
                : FixedSendBuff(channelBuffData(*obj), channelBuffSize(*obj))
                , mObj(std::move(obj))
            {}
        };

        template <typename F>
        class  RefSendBuff :public FixedSendBuff {
        public:
            const F& mObj;
            RefSendBuff(const F& obj)
                : mObj(obj)
            {   // set must be called after the move in case channelBuffData(mObj) != channelBuffData(obj)
                set(channelBuffData(mObj), channelBuffSize(mObj));
            }
        };

        class FixedRecvBuff : public BasicSizedBuff, public RecvOperation
        {
        public:
            FixedRecvBuff(std::future<void>& fu)
            {
                fu = mPromise.get_future();
            }

            FixedRecvBuff(const u8* data, u64 size, std::future<void>& fu)
                : BasicSizedBuff(data, size)
            {
                fu = mPromise.get_future();
            }

            io_completion_handle mComHandle;
            ChannelBase* mBase;
            std::promise<void> mPromise;

            void asyncPerform(ChannelBase* base, io_completion_handle completionHandle) override;
            void cancel(std::string reason) override
            {
                mPromise.set_exception(
                    std::make_exception_ptr(
                        CanceledOperation(std::move(reason))));
            };
            std::string toString() const override;

            virtual void resizeBuffer(u64) {}
        };

        template <typename F>
        class  RefRecvBuff :public FixedRecvBuff {
        public:
            const F& mObj;
            RefRecvBuff(const F& obj, std::future<void>& fu)
                : FixedRecvBuff(fu)
                , mObj(obj)
            {   // set must be called after the move in case channelBuffData(mObj) != channelBuffData(obj)
                set(channelBuffData(mObj), channelBuffSize(mObj));
            }
        };

        template <typename F>
        class ResizableRefRecvBuff : public FixedRecvBuff {
        public:
            ResizableRefRecvBuff() = delete;
            F& mObj;

            ResizableRefRecvBuff(F& obj, std::future<void>& fu)
                : FixedRecvBuff(fu)
                , mObj(obj)
            {}

            virtual void resizeBuffer(u64 size) override
            {
                channelBuffResize(mObj, size);
                mBuffs[1] = boost::asio::buffer((void*)channelBuffData(mObj), channelBuffSize(mObj));
            }
        };






        template< typename T>
        class WithCallback : public T
        {
        public:

            template<typename CB, typename... Args>
            WithCallback(CB&& cb, Args&&... args)
                : T(std::forward<Args>(args)...)
                , mCallback(std::forward<CB>(cb))
            {}

            std::function<void()> mCallback;

            void asyncPerform(ChannelBase* base, io_completion_handle completionHandle) override
            {
                T::asyncPerform(base, [this, h = std::move(completionHandle)](const error_code& ec, u64 bytes) mutable
                {
                    h(ec, bytes);
                    mCallback();
                });
            }
        };

        template< typename T>
        class WithPromise : public T
        {
        public:

            template<typename... Args>
            WithPromise(std::future<void>& f,Args&&... args)
                : T(std::forward<Args>(args)...)
            {
                f = mPromise.get_future();
            }

            std::promise<void> mPromise;

            void asyncPerform(ChannelBase* base, io_completion_handle completionHandle) override
            {
                T::asyncPerform(base, [this, h = std::move(completionHandle)](const error_code& ec, u64 bytes) mutable
                {
                    if (ec) mPromise.set_exception(std::make_exception_ptr(
                        CanceledOperation("network send error: " + ec.message() + "\n" LOCATION)));
                    else mPromise.set_value();

                    h(ec, bytes);
                });
            }

            void cancel(std::string reason) override
            {
                mPromise.set_exception(
                    std::make_exception_ptr(
                        CanceledOperation(std::move(reason))));

                T::cancel(reason);
            }
        };


    }
}
