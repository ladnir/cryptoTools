#pragma once
#include <iterator>
#include "Defines.h"
namespace osuCrypto
{
	template<typename T, T step = 1>
	class Increment
	{
	public:
		inline void operator()(T& v) const
		{
			v += step;
		}
	};
	template<typename T, T step = 1>
	class Deccrement
	{
	public:
		inline void operator()(T& v) const
		{
			v -= step;
		}
	};

	template<typename T, typename Inc = Increment<T>>
	class Range
	{
	public:

		struct Iterator
		{
			T mVal;
			Inc mInc;

			template<typename I>
			Iterator(T&& v,I&&i)
				: mVal(std::forward<T>(v))
				, mInc(std::forward<I>(i))
			{}

			T operator*() const { return mVal; }

			Iterator& operator++()
			{
				mInc(mVal);
				return *this;
			}
			Iterator operator++(int) const
			{
				auto v = *this;
				mInc(v.mVal);
				return v;
			}

			bool operator==(const Iterator& v) const
			{
				return v.mVal == mVal;
			}

			bool operator!=(const Iterator& v) const
			{
				return v.mVal != mVal;
			}
		};

		Iterator mBegin, mEnd;

		auto begin() const { return mBegin; }
		auto end() const { return mEnd; }

		Range(T&& begin, T&& end, Inc&& step)
			: mBegin(std::forward<T>(begin), step)
			, mEnd(std::forward<T>(end), std::move(step))
		{}
	};



	template<typename T, typename V, typename Inc>
	Range<T, Inc> rng(V&& begin, V&& end, Inc&& inc)
	{
		return Range<T, Inc>(std::forward<V>(begin), std::forward<V>(end), std::forward<Inc>(inc));
	}

	template<typename T = u64, typename V>
	Range<T> rng(V&& begin, V&& end)
	{
		using Inc = Increment<T, 1>;
		return rng<T,V, Inc>(std::forward<T>(begin), std::forward<T>(end), Inc{});
	}

	template<typename T = u64, typename V>
	Range<T> rng(V&& end)
	{
		return rng<T,V>(0, std::forward<V>(end));
	}



}