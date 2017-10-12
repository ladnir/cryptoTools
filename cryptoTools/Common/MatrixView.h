#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <array>

namespace osuCrypto
{

    template<class T>
    class MatrixView
    {
    public:

        using iterator = gsl::details::span_iterator<gsl::span<T>, false>;
        using const_iterator = gsl::details::span_iterator<gsl::span<T>, true>;
        using reverse_iterator = std::reverse_iterator<iterator>;
        using const_reverse_iterator = std::reverse_iterator<const_iterator>;
        //using iterator = gsl::span<T>::iterator;

        typedef T value_type;
        typedef value_type* pointer;
        typedef u64 size_type;

        
        MatrixView()
            :mStride(0)
        {
        }

        MatrixView(const MatrixView& av) :
            mView(av.mView),
            mStride(av.mStride)
        { }

        MatrixView(pointer data, size_type numRows, size_type stride) :
            mView(data, numRows * stride),
            mStride(stride)
        {}

        MatrixView(pointer start, pointer end, size_type stride) :
            mView(start, end - ((end - start) % stride)),
            mStride(stride)
        {
        }

        template <class Iter>
        MatrixView(Iter start, Iter end, size_type stride, typename Iter::iterator_category *p = 0) :
            mView(start, end/* - ((end - start) % stride)*/),
            mStride(stride)
        {
            std::ignore = p;
        }

        template<template<typename, typename...> class C, typename... Args>
        MatrixView(const C<T, Args...>& cont, size_type stride, typename C<T, Args...>::value_type* p = 0) :
            MatrixView(cont.begin(), cont.end(), stride)
        {
            std::ignore = p;
        }

        const MatrixView<T>& operator=(const MatrixView<T>& copy)
        {
            mView = copy.mView;
            mStride = copy.mStride;
            return copy;
        }


        void reshape(size_type rows, size_type columns)
        {
            if (rows * columns != size())
                throw std::runtime_error(LOCATION);

            mView = span<T>(mView.data(), rows * columns);
            mStride = columns;
        }

        const size_type size() const { return mView.size(); }
        const size_type stride() const { return mStride; }

        std::array<size_type, 2> bounds() const { return { stride() ? size() / stride() : 0 , stride() }; }

        pointer data() const { return mView.data(); };

        iterator begin() const { return mView.begin(); };
        iterator end() const { return mView.end(); }

        T& operator()(size_type rowIdx, size_type colIdx)
        {
            return mView[rowIdx * stride() + colIdx];
        }

		const T& operator()(size_type rowIdx, size_type colIdx) const
		{
			return mView[rowIdx * stride() + colIdx];
		}

        span<T> operator[](size_type rowIdx) const
        {
#ifndef NDEBUG
            if (rowIdx >= mView.size() / stride()) throw std::runtime_error(LOCATION);
#endif

            return span<T>(mView.data() + rowIdx * stride(), stride());
        }



    protected:
        span<T> mView;
        size_type mStride;


    };
}

