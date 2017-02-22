#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <vector>
#include <array>

#include <cryptoTools/gsl/span>

namespace osuCrypto {


    template <typename T>
    using ArrayView = gsl::span<T>;

//#ifndef NDEBUG
//    template<typename T>
//    struct ArrayIterator
//    {
//        ArrayIterator(T*begin, T* cur, T* end)
//            :mBegin(begin), mCur(cur), mEnd(end)
//        {
//            if (mCur > mEnd) throw std::runtime_error("iter went past end. " LOCATION);
//            if (mCur && mCur < mBegin - 1) throw std::runtime_error("iter went past begin. " LOCATION);
//        }
//        T* mBegin, *mCur, *mEnd;
//
//        ArrayIterator<T>& operator++() {
//            ++mCur;
//            if (mCur > mEnd) throw std::runtime_error("iter went past end. " LOCATION);
//            return *this;
//        }
//
//        ArrayIterator<T> operator++(int) {
//            ++mCur;
//            return ArrayIterator<T>(mBegin, mCur - 1, mEnd);
//        }
//        ArrayIterator<T>& operator--() {
//            --mCur;
//            if (mCur < mBegin - 1) throw std::runtime_error("iter went past end. " LOCATION);
//            return *this;
//        }
//
//        ArrayIterator<T> operator--(int) {
//            --mCur;
//            return ArrayIterator<T>(mBegin, mCur + 1, mEnd);
//        }
//
//        ArrayIterator<T> operator+(i64 i) {
//            return ArrayIterator<T>(mBegin, mCur + i, mEnd);
//        }
//
//        ArrayIterator<T>& operator+=(i64 i) {
//            mCur += i;
//            if (mCur > mEnd) throw std::runtime_error("iter went past end. " LOCATION);
//            return *this;
//        }
//
//        ArrayIterator<T> operator-(i64 i) {
//            return ArrayIterator<T>(mBegin, mCur - i, mEnd);
//        }
//
//        ArrayIterator<T>& operator-=(i64 i) {
//            mCur -= i;
//            if (mCur < mBegin - 1) throw std::runtime_error("iter went past end. " LOCATION);
//            return *this;
//        }
//
//        i64 operator-(T* i) {
//            return mCur - i;
//        }
//
//        T& operator*() {
//            if (mCur >= mEnd || mCur < mBegin)throw std::runtime_error("deref past begin or end. " LOCATION);
//            return *mCur;
//        }
//
//        T* operator->()
//        {
//            return mCur;
//        }
//
//        T& operator[](i64 i) {
//            if (mCur + i >= mEnd || mCur + i < mBegin)throw std::runtime_error("idx went past begin or end. " LOCATION);
//            return mCur[i];
//        }
//
//        bool operator<(const ArrayIterator<T>& cmp) { return mCur < cmp.mCur; }
//        bool operator>(const ArrayIterator<T>& cmp) { return mCur > cmp.mCur; }
//        bool operator<=(const ArrayIterator<T>& cmp) { return mCur <= cmp.mCur; }
//        bool operator>=(const ArrayIterator<T>& cmp) { return mCur >= cmp.mCur; }
//        bool operator==(const ArrayIterator<T>& cmp) { return mCur == cmp.mCur; }
//        bool operator!=(const ArrayIterator<T>& cmp) { return mCur != cmp.mCur; }
//
//        ArrayIterator<T>& operator=(const ArrayIterator<T>& cmp)
//        {
//            mBegin = cmp.mBegin; mCur = cmp.mCur; mEnd = cmp.mEnd; return *this;
//        }
//
//        operator T*() { return mCur; }
//    };
//#endif
//
//    template<class T>
//    class ArrayView
//    {
//
//        T* mData;
//        u64 mSize;
//        bool mOwner;
//    public:
//
//        typedef T* pointer;
//        typedef T value_type;
//
//        ArrayView()
//            :mData(nullptr),
//            mSize(0),
//            mOwner(false)
//        {
//        }
//
//        ArrayView(const ArrayView& av) :
//            mData(av.mData),
//            mSize(av.mSize),
//            mOwner(false)
//        { }
//
//        ArrayView(ArrayView&& av) :
//            mData(av.mData),
//            mSize(av.mSize),
//            mOwner(av.mOwner)
//        {
//            av.mData = nullptr;
//            av.mSize = 0;
//            av.mOwner = false;
//        }
//
//        ArrayView(u64 size) :
//            mData(new T[size]),
//            mSize(size),
//            mOwner(true)
//        { }
//
//        ArrayView(T* data, u64 size, bool owner = false) :
//            mData(data),
//            mSize(size),
//            mOwner(owner)
//        {}
//
//        //template<typename Container>
//
//        template <class Iter>
//        ArrayView(Iter start, Iter end, typename Iter::iterator_category *p = 0) :
//            mData(&*start),
//            mSize(end - start),
//            mOwner(false)
//        {
//            //static_assert(std::is_same<typename Iter::value_type, T>::value, "Iter iter must have the same value_type as ArrayView");
//            //(void*)p;
//            std::ignore = p;
//
//        }
//
//        ArrayView(T* begin, T* end, bool owner) :
//            mData(begin),
//            mSize(end - begin),
//            mOwner(owner)
//        {}
//
//
//        template<template<typename, typename...> class C, typename... Args>
//        ArrayView(const C<T, Args...>& cont, typename C<T, Args...>::value_type* p = 0) :
//            mData(((C<T, Args...>&)cont).data()),
//            mSize((((C<T, Args...>&)cont).end() - ((C<T, Args...>&)cont).begin())),
//            mOwner(false)
//        {
//            std::ignore = p;
//            //static_assert(std::is_same<typename C<T, Args...>::value_type, T>::value, "Container cont must have the same value_type as ArrayView");
//            //(void*)p;
//        }
//
//        //ArrayView(std::vector<T>& container)
//        //    : mData(container.data()),
//        //    mSize(container.size()),
//        //    mOwner(false)
//        //{
//        //}
//
//        template<size_t n>
//        ArrayView(std::array<T,n>& container)
//            : mData(container.data()),
//            mSize(container.size()),
//            mOwner(false)
//        {
//        }
//
//        ~ArrayView()
//        {
//            if (mOwner) delete[] mData;
//        }
//
//
//        const ArrayView<T>& operator=(const ArrayView<T>& copy)
//        {
//            mData = copy.mData;
//            mSize = copy.mSize;
//            mOwner = false;
//
//            return copy;
//        }
//
//
//        u64 size() const { return mSize; }
//
//        T* data() const { return mData; };
//
//#ifdef NDEBUG
//        T* begin() const { return mData; };
//        T* end() const { return mData + mSize; }
//#else
//        ArrayIterator<T> begin() const
//        {
//            T* b = mData;
//            T* c = mData;
//            T* e = (T*)mData + (mSize);
//
//            return ArrayIterator<T>(b, c, e);
//        };
//        ArrayIterator<T> end() const {
//            T* e = (T*)mData + (mSize);
//            return ArrayIterator<T>(mData, e, e);
//        }
//#endif
//
//        //T& operator[](int idx) { if (idx >= mSize) throw std::runtime_error(LOCATION); return mData[idx]; }
//        inline T& operator[](u64 idx) const
//        {
//#ifndef NDEBUG
//            if (idx >= mSize) throw std::runtime_error(LOCATION);
//#endif
//
//            return mData[idx];
//        }
//    };

    template<typename T>
    ArrayView<T> makeArrayView(T* data, u64 size)
    {
        return ArrayView<T>(data, size);
    }
}