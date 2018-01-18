#pragma once
#ifdef USE_FULL_GSL
#include <cryptoTools/gsl/multi_span>
#else
#include <cryptoTools/gsl/gls-lite.hpp>
#endif
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/MatrixView.h>

namespace osuCrypto
{

    template<typename T>
    class Matrix : public MatrixView<T>
    {

    public:
        Matrix()
        {}

        Matrix(u64 rows, u64 columns)
            : MatrixView<T>(new T[rows * columns](), rows, columns)
        {}



        Matrix(const MatrixView<T>& copy)
            : MatrixView<T>(new T[copy.size()], copy.bounds()[0], copy.stride())
        {
            memcpy(MatrixView<T>::mView.data(), copy.data(), copy.mView.sizeBytes());
        }

        Matrix(Matrix<T>&& copy)
            : MatrixView<T>(copy.data(), copy.bounds()[0] , copy.stride())
        {
            copy.mView = span<T>();
            copy.mStride = 0;
        }


        ~Matrix()
        {
            delete[] MatrixView<T>::mView.data();
        }


        const Matrix<T>& operator=(const Matrix<T>& copy)
        {
            delete[] MatrixView<T>::mView.data();
            MatrixView<T>::mView = span<T>(new T[copy.size()], copy.size());

            memcpy(MatrixView<T>::mView.data(), copy.data(), copy.mView.size_bytes());

            return copy;
        }


        void resize(u64 rows, u64 columns)
        {
            auto old = MatrixView<T>::mView;
            
            MatrixView<T>::mView = span<T>(new T[rows * columns](), rows * columns);

            auto min = std::min<u64>(old.size(), rows * columns) * sizeof(T);
            memcpy(MatrixView<T>::mView.data(), old.data(), min);

            delete[] old.data();

            MatrixView<T>::mStride = columns;
        }


		// return the internal memory, stop managing its lifetime, and set the current container to null.
		T* release()
		{
			auto ret = MatrixView<T>::mView.data();
			MatrixView<T>::mView = {};
			return ret;
		}
    };


}
