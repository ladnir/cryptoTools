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
            delete[] mView.data();
        }



        void resize(u64 rows, u64 columns)
        {
            auto old = mView;
            
            mView = ArrayView<T>(new T[rows * columns]());

            auto min = std::min(old.size(), rows * columns) * sizeof(T);
            memcpy(mView.data(), old.data(), min);

            delete[] old.data();

            mBounds[0] = rows;
            mBounds[1] = columns;
        }

    };


}
