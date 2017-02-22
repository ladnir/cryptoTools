#pragma once
#include <cryptoTools/gsl/multi_span>
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

        ~Matrix()
        {
            delete[] MatrixView<T>::mView.data();
        }



        void resize(u64 rows, u64 columns)
        {
            auto old = MatrixView<T>::mView;
            
            MatrixView<T>::mView = ArrayView<T>(new T[rows * columns](), rows * columns);

            auto min = std::min<u64>(old.size(), rows * columns) * sizeof(T);
            memcpy(MatrixView<T>::mView.data(), old.data(), min);

            delete[] old.data();

            MatrixView<T>::mStride = columns;
        }

    };


}
