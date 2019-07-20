#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>

#include <string> 
#include <future> 
#include <functional> 
#include <memory> 
#include <boost/asio.hpp>
#include <system_error>
#include  <type_traits>
#include <list>
#include <boost/variant.hpp>

//#define CHANNEL_LOGGING

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
                , mStorage((T*)new u8[cap * sizeof(T)], cap)
            {};

            ~BaseQueue()
            {
                while (size())
                {
                    pop_front();
                }

                delete[] (u8*)mStorage.data();
            }

            std::atomic<u64> mPopIdx;
            std::atomic<u64> mPushIdx;
            span<T> mStorage;

            u64 capacity() const { return mStorage.size(); }
            u64 size() const { return mPushIdx.load(std::memory_order_relaxed) - mPopIdx.load(std::memory_order_relaxed); }
            bool isFull() const { return size() == capacity(); }
            bool isEmpty() const { return size() == 0; }

            void push_back(T&& v)
            {
                if (isFull()) // synchonize mPopIdx with #2
                    throw std::runtime_error("Queue is full " LOCATION);

                auto pushIdx = mPushIdx.load(std::memory_order_relaxed) % capacity();
                new (&mStorage[pushIdx]) T(std::move(v));

                mPushIdx.fetch_add(1, std::memory_order_release); // synchonize storage with #1
            }

            T& front()
            {
                auto popIdx = mPopIdx.load(std::memory_order_relaxed);  // synchonize mPopIdx with #2
                auto pushIdx = mPushIdx.load(std::memory_order_acquire); // synchonize storage with #1
                if (popIdx == pushIdx)
                    throw std::runtime_error("queue is empty. " LOCATION);

                return mStorage[popIdx % capacity()];
            }

            void pop_front()
            {
                if (isEmpty())
                    throw std::runtime_error("queue is empty. " LOCATION);

                auto popIdx = mPopIdx.load(std::memory_order_relaxed);
                mStorage[popIdx % capacity()].~T();
                mPopIdx.fetch_add(1, std::memory_order_relaxed);
            }
        };

        std::list<BaseQueue> mQueues;
        mutable std::mutex mMtx;

        SpscQueue(u64 cap = 64)
        {
            mQueues.emplace_back(cap);
        }

        bool isEmpty() const { 
            std::lock_guard<std::mutex> l(mMtx);
            return mQueues.back().isEmpty(); 
        }

        void push_back(T&& v)
        {
            std::lock_guard<std::mutex> l(mMtx);
            if (mQueues.back().isFull())
            {
                // create a new subQueue of four times the size.
                //std::lock_guard<std::mutex> l(mMtx);
                mQueues.emplace_back(mQueues.back().capacity() * 4);
            }

            mQueues.back().push_back(std::move(v));
        }

        T& front()
        {
            std::lock_guard<std::mutex> l(mMtx);
            return mQueues.front().front();
        }

        void pop_front()
        {
            std::lock_guard<std::mutex> l(mMtx);
            mQueues.front().pop_front();

            if (mQueues.front().size() == 0 && mQueues.size() > 1)
            {
                // a larger subqueue was added and the current one is
                // empty. Migrate to the larger one.
                //std::lock_guard<std::mutex> l(mMtx);
                mQueues.pop_front();
            }
        }
    };


    template<typename T, int StorageSize = 248 /* makes the whole thing 256 bytes */>
    class SBO_ptr
    {
    public:
        struct SBOInterface
        {
            virtual ~SBOInterface() {};

            // assumes dest is uninitialized and calls the 
            // placement new move constructor with this as 
            // dest destination.
            virtual void moveTo(SBO_ptr<T, StorageSize>& dest) = 0;
        };

        template<typename U>
        struct Impl : SBOInterface
        {

            template<typename... Args,
                typename Enabled =
                typename std::enable_if<
                std::is_constructible<U, Args...>::value
                >::type
            >
                Impl(Args&&... args)
                :mU(std::forward<Args>(args)...)
            {}

            void moveTo(SBO_ptr<T, StorageSize>& dest) override
            {
                Expects(dest.get() == nullptr);
                dest.New<U>(std::move(mU));
            }

            U mU;
        };

        using base_type = T;
        using Storage = typename std::aligned_storage<StorageSize>::type;
        
        template<typename U>
        using Impl_type =  Impl<U>;

        T* mData = nullptr;
        Storage mStorage;

        SBO_ptr() = default;
        SBO_ptr(const SBO_ptr<T>&) = delete;

        SBO_ptr(SBO_ptr<T>&& m)
        {
            *this = std::forward<SBO_ptr<T>>(m);
        }

        ~SBO_ptr()
        {
            destruct();
        }


        SBO_ptr<T, StorageSize>& operator=(SBO_ptr<T>&& m)
        {
            destruct();

            if (m.isSBO())
            {
                m.getSBO().moveTo(*this);
            }
            else
            {
                std::swap(mData, m.mData);
            }
            return *this;
        }

        template<typename U, typename... Args >
        typename std::enable_if<
            (sizeof(Impl_type<U>) <= sizeof(Storage)) &&
            std::is_base_of<T, U>::value &&
            std::is_constructible<U, Args...>::value
        >::type
            New(Args&&... args)
        {
            destruct();

            // Do a placement new to the local storage and then take the
            // address of the U type and store that in our data pointer.
            Impl<U>* ptr = (Impl<U>*)&getSBO();
            new (ptr) Impl<U>(std::forward<Args>(args)...);
            mData = &(ptr->mU);
        }

        template<typename U, typename... Args >
        typename std::enable_if<
            (sizeof(Impl_type<U>) > sizeof(Storage)) &&
            std::is_base_of<T, U>::value &&
            std::is_constructible<U, Args...>::value
                >::type
            New(Args&&... args)
        {
            destruct();

            //int n1 = sizeof(Impl_type<U>);
            //int n2 = sizeof(Storage);

            // this object is too big, use the allocator. Local storage
            // will be unused as denoted by (isSBO() == false).
            mData = new U(std::forward<Args>(args)...);
        }


        bool isSBO() const 
        { 
            auto begin = (u8*)this;
            auto end = begin + sizeof(SBO_ptr<T, StorageSize>);
            return 
                ((u8*)get() >= begin) &&
                ((u8*)get() < end); 
        }

        T* operator->() { return get(); }
        T* get() { return mData; }

        const T* operator->() const { return get(); }
        const T* get() const  { return mData; }


    //private:

        void destruct()
        {
            if (isSBO())
                // manually call the virtual destructor.
                getSBO().~SBOInterface();
            else if(get())
                // let the compiler call the destructor
                delete get();

            mData = nullptr;
        }





        SBOInterface& getSBO()
        {
            return *(SBOInterface*)&mStorage;
        }

        const SBOInterface& getSBO() const
        {
            return *(SBOInterface*)&mStorage;
        }
    };


    template<typename T, typename U, typename... Args>
    typename  std::enable_if<
        std::is_constructible<U, Args...>::value &&
        std::is_base_of<T, U>::value, SBO_ptr<T>>::type
        make_SBO_ptr(Args&&... args)
    {
        SBO_ptr<T> t;
        t.template New<U>(std::forward<Args>(args)...);
        return (t);
    }


    namespace details
    {

        class operation_canceled :
            public boost::system::error_category
        {
        public:
            const char *name() const noexcept { return "cryptoTools"; }
            std::string message(int ev) const { return "local party called cancel on the operation."; }
        };
        extern operation_canceled opCancel;

        class SendOperation
        {
        public:
            SendOperation() = default;
            SendOperation(SendOperation&& copy) = default;
            SendOperation(const SendOperation& copy) = default;

            virtual ~SendOperation() {}

            virtual void asyncPerform(ChannelBase* base, io_completion_handle&& completionHandle) = 0;
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
            RecvOperation(RecvOperation&& copy) = default;
            RecvOperation(const RecvOperation& copy) = default;

            virtual ~RecvOperation() {}

            virtual void asyncPerform(ChannelBase* base, io_completion_handle&& completionHandle) = 0;
            virtual void cancel(std::string reason) = 0;
            virtual std::string toString() const;

#ifdef CHANNEL_LOGGING
            u64 mIdx;
#endif
        };

        using size_header_type = u32;

        // A class for sending or receiving data over a channel. 
        // Datam sent/received with this type sent over the network 
        // with a header denoting its size in bytes.
        class BasicSizedBuff
        {
        public:

            BasicSizedBuff(BasicSizedBuff&& v)
            {
                mHeaderSize = v.mHeaderSize;
                mBuff = v.mBuff;
                v.mBuff = {};
            }
            BasicSizedBuff() = default;

            BasicSizedBuff(const u8* data, u64 size)
                : mHeaderSize(size_header_type(size))
                , mBuff{ (u8*)data,  span<u8>::size_type(size) }
            {
                Expects(size < std::numeric_limits<size_header_type>::max());
            }

            void set(const u8* data, u64 size)
            {
                Expects(size < std::numeric_limits<size_header_type>::max());
                mBuff = {(u8*)data, span<u8>::size_type(size)};
            }

            inline u64 getHeaderSize() const { return mHeaderSize; }
            inline u64 getBufferSize() const { return mBuff.size(); }
            inline u8* getBufferData() { return mBuff.data(); }

            inline std::array<boost::asio::mutable_buffer, 2> getSendBuffer()
            {
                Expects(mBuff.size());
                mHeaderSize = size_header_type(mBuff.size());
                return { { getRecvHeaderBuffer(), getRecvBuffer() } };
            }

            inline boost::asio::mutable_buffer getRecvHeaderBuffer(){
                return boost::asio::mutable_buffer(&mHeaderSize, sizeof(size_header_type));
            }

            inline boost::asio::mutable_buffer getRecvBuffer(){
                return boost::asio::mutable_buffer(mBuff.data(), mBuff.size());
            }

        protected:
            size_header_type mHeaderSize;
            span<u8> mBuff;
        };




        class FixedSendBuff : public BasicSizedBuff, public SendOperation
        {
        public:
            FixedSendBuff() = default;
            FixedSendBuff(const u8* data, u64 size)
                : BasicSizedBuff(data, size)
            {}

            FixedSendBuff(FixedSendBuff&& v) = default;

            void asyncPerform(ChannelBase* base, io_completion_handle&& completionHandle) override;
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

            MoveSendBuff(MoveSendBuff&&v)
                : MoveSendBuff(std::move(v.mObj))
            {}
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

            MoveSendBuff(MoveSendBuff<std::unique_ptr<T>>&& v)
                : MoveSendBuff(std::move(v.mObj))
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

            MoveSendBuff(MoveSendBuff<std::unique_ptr<T>>&& v)
                : MoveSendBuff(std::move(v.mObj))
            {}
        };

        template <typename F>
        class  RefSendBuff :public FixedSendBuff {
        public:
            const F& mObj;
            RefSendBuff(const F& obj)
                : FixedSendBuff(channelBuffData(*obj), channelBuffSize(*obj))
                , mObj(obj)
            {}

            RefSendBuff(RefSendBuff<F>&& v)
                :RefSendBuff(v.obj)
            {}
        };


        class FixedRecvBuff : public BasicSizedBuff, public RecvOperation
        {
        public:

            io_completion_handle mComHandle;
            ChannelBase* mBase;
            std::promise<void> mPromise;


            FixedRecvBuff(FixedRecvBuff&& v)
                : BasicSizedBuff(v.getBufferData(), v.getBufferSize())
                , mComHandle(std::move(v.mComHandle))
                , mBase(v.mBase)
                , mPromise(std::move(v.mPromise))
            {}

            FixedRecvBuff(std::future<void>& fu)
            {
                fu = mPromise.get_future();
            }

            FixedRecvBuff(const u8* data, u64 size, std::future<void>& fu)
                : BasicSizedBuff(data, size)
            {
                fu = mPromise.get_future();
            }

            void asyncPerform(ChannelBase* base, io_completion_handle&& completionHandle) override;
            void cancel(std::string reason) override
            {
                mPromise.set_exception(
                    std::make_exception_ptr(
                        CanceledOperation(std::move(reason))));

                //error_code ec{ 1, opCancel };

                //mComHandle(ec, 0);
                    
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

            RefRecvBuff(RefRecvBuff<F>&& v)
                : FixedRecvBuff(std::move(v))
                , mObj(v.mObj)
            {}

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

            ResizableRefRecvBuff(ResizableRefRecvBuff<F>&& v)
                : FixedRecvBuff(std::move(v))
                , mObj(v.mObj)
            {}

            virtual void resizeBuffer(u64 size) override
            {
                channelBuffResize(mObj, size);
                set((u8*)channelBuffData(mObj), channelBuffSize(mObj));
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

            WithCallback(WithCallback<T>&& v)
                : T(std::move(v))
                , mCallback(std::move(v.mCallback))
            {}
            boost::variant<
                std::function<void()>,
                std::function<void(const error_code&)>>mCallback;
            io_completion_handle mWithCBCompletionHandle;

            void asyncPerform(ChannelBase* base, io_completion_handle&& completionHandle) override
            {
                mWithCBCompletionHandle = std::move(completionHandle);

                T::asyncPerform(base, [this](const error_code& ec, u64 bytes) mutable
                {
                    if (mCallback.which() == 0)
                    {
                        auto& c = boost::get<std::function<void()>>(mCallback);
                        if(c)
                            c();
                        c = {};
                    }
                    else
                    {
                        auto& c = boost::get<std::function<void(const error_code&)>>(mCallback);
                        if (c)
                            c(ec);
                        c = {};
                    }

                    mWithCBCompletionHandle(ec, bytes);
                });
            }

            void cancel(std::string reason) override
            {
                T::cancel(reason);

                if (mCallback.which() == 1)
                {
                    error_code ec{ 1, opCancel };
                    auto& c = boost::get<std::function<void(const error_code&)>>(mCallback);
                    if (c)
                        c(ec);
                    c = {};
                }
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

            WithPromise(WithPromise<T>&& v)
                : T(std::move(v))
                , mPromise(std::move(v.mPromise))
            {}


            std::promise<void> mPromise;
            io_completion_handle mWithPromCompletionHandle;

            void asyncPerform(ChannelBase* base, io_completion_handle&& completionHandle) override
            {
                mWithPromCompletionHandle = std::move(completionHandle);

                T::asyncPerform(base, [this](const error_code& ec, u64 bytes) mutable
                {
                    if (ec) mPromise.set_exception(std::make_exception_ptr(
                        CanceledOperation("network send error: " + ec.message() + "\n" LOCATION)));
                    else mPromise.set_value();

                    mWithPromCompletionHandle(ec, bytes);
                });
            }

            void cancel(std::string reason) override
            {
                mPromise.set_exception(
                    std::make_exception_ptr(
                        CanceledOperation(reason)));

                T::cancel(std::move(reason));
            }
        };


    }
}
