#include "cryptoTools/Common/Defines.h"
#include <future>
#include <atomic>

namespace osuCrypto
{

    class ThreadBarrier
    {
        std::promise<void> mProm;
        std::shared_future<void> mFuture;
        std::atomic<u64> mCount;
    public:
        ThreadBarrier(u64 count)
            : mFuture(mProm.get_future())
            , mCount(count)
        {
        }

        void decremenetWait()
        {
            if (--mCount)
            {
                mFuture.get();
            }
            else
            {
                mProm.set_value();
            }
        }


        ThreadBarrier& operator--()
        {
            decremenetWait();
            return *this;
        }


        void reset(u64 count)
        {
            mCount = count;
            mProm = std::promise<void>();
            mFuture = mProm.get_future();
        }

    };
}
