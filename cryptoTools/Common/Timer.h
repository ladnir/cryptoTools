#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include <list>
#include <chrono>
#include <string>
#include <mutex>
namespace osuCrypto
{ 

    class Timer
    {
    public:

        typedef std::chrono::system_clock::time_point timeUnit;

        //struct TimerSpan
        //{
        //    TimerSpan(Timer&t, std::string name)
        //        : mTimer(&t)
        //        , mName(std::move(name))
        //        , mBegin(timeUnit::clock::now())
        //    {}
        //    ~TimerSpan()
        //    {
        //        end();
        //    }
        //    void end()
        //    {
        //        if (mTimer)
        //        {
        //            mTimer->addSpan(mBegin, timeUnit::clock::now());
        //            mTimer = nullptr;
        //        }
        //    }
        //    Timer* mTimer;
        //    std::string mName;
        //    timeUnit mBegin;
        //};
        //void addSpan(timeUnit begin, timeUnit end);


        std::list< std::pair<timeUnit, std::string>> mTimes;
        bool mLocking;
        std::mutex mMtx;

        Timer(bool locking = false)
            :mLocking(locking)
        {
            reset();
        }

        const timeUnit& setTimePoint(const std::string& msg);


        friend std::ostream& operator<<(std::ostream& out, const Timer& timer);

        void reset();
    };

	extern Timer gTimer;
    class TimerAdapter
    {
    public:
        virtual void setTimer(Timer& timer)
        {
            mTimer = &timer;
        }

        Timer& getTimer()
        {
            if (mTimer)
                return *mTimer;

            throw std::runtime_error("Timer net set. ");
        }

        Timer::timeUnit setTimePoint(const std::string& msg)
        {
            if(mTimer) return getTimer().setTimePoint(msg);
            else return Timer::timeUnit::clock::now();
        }

        Timer* mTimer = nullptr;
    };


}