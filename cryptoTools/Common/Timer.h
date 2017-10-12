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
        typedef std::chrono::system_clock::time_point timeUnit;

        timeUnit mStart;
        std::list< std::pair<timeUnit, std::string>> mTimes;
        bool mLocking;
        //std::mutex mMtx;
    public: 
        Timer(bool locking = false)
        :mStart(Timer::timeUnit::clock::now()) 
            , mLocking(locking)
        {}
        //Timer(const Timer&);

        const timeUnit& setTimePoint(const std::string& msg);


        friend std::ostream& operator<<(std::ostream& out, const Timer& timer);


        void reset();
    };
	extern Timer gTimer;

}