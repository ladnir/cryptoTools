#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "Common/Defines.h"
#include <string>
#include <ostream>
#include <mutex>

namespace osuCrypto
{


    enum class Color {
        LightGreen = 2,
        LightGrey = 3,
        LightRed = 4,
        OffWhite1 = 5,
        OffWhite2 = 6,
        Grey = 8,
        Green = 10,
        Blue = 11,
        Red = 12,
        Pink = 13,
        Yellow = 14,
        White = 15
    };

    extern const Color ColorDefault;


    std::ostream& operator<<(std::ostream& out, Color color);

    enum IoStream
    {
        lock,
        unlock
    };

    extern std::mutex gIoStreamMtx;

    std::ostream& operator<<(std::ostream& out, IoStream color);


    void setThreadName(const std::string name);
    void setThreadName(const char* name);

}
