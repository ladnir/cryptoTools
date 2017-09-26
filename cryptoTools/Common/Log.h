#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
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

	enum class IoStream
	{
		lock,
		unlock
	};

	extern std::mutex gIoStreamMtx;

	struct ostreamLock
	{
		std::ostream& out;
		std::lock_guard<std::mutex> mLock;

		ostreamLock(std::ostream& o) :
			out(o),
			mLock(gIoStreamMtx)
		{}

		template<typename T>
		ostreamLock& operator<<(const T& v)
		{
			out << v;
			return *this;
		}

		template<typename T>
		ostreamLock& operator<<(T& v)
		{
			out << v;
			return *this;
		}
		ostreamLock& operator<< (std::ostream& (*v)(std::ostream&))
		{
			out << v;
			return *this;
		}
		ostreamLock& operator<< (std::ios& (*v)(std::ios&))
		{
			out << v;
			return *this;
		}
		ostreamLock& operator<< (std::ios_base& (*v)(std::ios_base&))
		{
			out << v;
			return *this;
		}
	};

	std::ostream& operator<<(std::ostream& out, IoStream color);


	void setThreadName(const std::string name);
	void setThreadName(const char* name);

}
