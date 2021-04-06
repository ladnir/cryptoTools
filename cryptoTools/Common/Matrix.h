#pragma once

#include <cryptoTools/Common/Defines.h>
#ifndef ENABLE_FULL_GSL
#include <cryptoTools/gsl/gls-lite.hpp>
#endif
#include <cryptoTools/Common/MatrixView.h>
#include <cstring>

namespace osuCrypto
{
    enum class AllocType
    {
        Uninitialized,
        Zeroed
    };

    template<typename T>
    class Matrix : public MatrixView<T>
    {
        u64 mCapacity = 0;
    public:
        Matrix() = default;

        Matrix(u64 rows, u64 columns, AllocType t = AllocType::Zeroed)
        {
            resize(rows, columns, t);
        }


        Matrix(const Matrix<T>& copy)
            : MatrixView<T>(new T[copy.size()], copy.bounds()[0], copy.stride())
            , mCapacity(copy.size())
        {
            memcpy(MatrixView<T>::mView.data(), copy.data(), copy.mView.size_bytes());
        }

        Matrix(const MatrixView<T>& copy)
            : MatrixView<T>(new T[copy.size()], copy.bounds()[0], copy.stride())
            , mCapacity(copy.size())
        {
            memcpy(MatrixView<T>::mView.data(), copy.data(), copy.size() * sizeof(T));
        }

        Matrix(Matrix<T>&& copy)
            : MatrixView<T>(copy.data(), copy.bounds()[0], copy.stride())
            , mCapacity(copy.mCapacity)
        {
            copy.mView = span<T>();
            copy.mStride = 0;
            copy.mCapacity = 0;
        }


        ~Matrix()
        {
            delete[] MatrixView<T>::mView.data();
        }


        const Matrix<T>& operator=(const Matrix<T>& copy)
        {
            resize(copy.rows(), copy.stride());
            auto b = copy.begin();
            auto e = copy.end();

            std::copy(b, e, MatrixView<T>::mView.begin());
            //memcpy(MatrixView<T>::mView.data(), copy.data(), copy.mView.size_bytes());
            return copy;
        }

        template<typename T2> 
        static 
            typename std::enable_if<std::is_trivially_constructible<T2>::value>::type 
            zeroFill(T2* begin, T2* end)
        {
            std::memset(begin, 0, (end-begin) * sizeof(T2));
        }

        template<typename T2>
        static
            typename std::enable_if<!std::is_trivially_constructible<T2>::value>::type
            zeroFill(T2* begin, T2* end)
        {
            std::fill(begin, end, T2{});
        }

        void resize(u64 rows, u64 columns, AllocType type = AllocType::Zeroed)
        {
            if (rows * columns > mCapacity)
            {
                mCapacity = rows * columns;
                auto old = MatrixView<T>::mView;

                if (type == AllocType::Zeroed)
                    MatrixView<T>::mView = span<T>(new T[mCapacity](), mCapacity);
                else
                    MatrixView<T>::mView = span<T>(new T[mCapacity], mCapacity);


                auto min = std::min<u64>(old.size(), mCapacity) * sizeof(T);
    
                if (min)
                    std::copy(old.begin(), old.end(), MatrixView<T>::mView.begin());

                delete[] old.data();

            }
            else
            {
                auto newSize = rows * columns;
                if (MatrixView<T>::size() && newSize > MatrixView<T>::size() && type == AllocType::Zeroed)
                {
                    auto b = MatrixView<T>::data() + MatrixView<T>::size();
                    auto e = b + newSize - MatrixView<T>::size();
                    zeroFill<T>(b, e);
                }

                MatrixView<T>::mView = span<T>(MatrixView<T>::data(), newSize);
            }

            MatrixView<T>::mStride = columns;
        }


        // return the internal memory, stop managing its lifetime, and set the current container to null.
        T* release()
        {
            auto ret = MatrixView<T>::mView.data();
            MatrixView<T>::mView = span<T>(nullptr, 0);
            mCapacity = 0;
            return ret;
        }


        bool operator==(const Matrix<T>&m) const
        {
            if (m.rows() != MatrixView<T>::rows() || m.cols() != MatrixView<T>::cols())
                return false;
            auto b0 = m.begin();
            auto e0 = m.end();
            auto b1 = MatrixView<T>::begin();
            return std::equal(b0,e0,b1);
        }
    };


}
