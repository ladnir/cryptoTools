#pragma once
#include "cryptoTools/gsl/multi_span.h"
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{

    template <typename T>
    using MatricView2 = gsl::multi_span<T, gsl::dynamic_range, gsl::dynamic_range>;

    template<typename T>
    class Matrix : private MatricView2<T>
    {

        //MatricView2<T> mView;

    public:
        Matrix()
        {}

        Matrix(u64 rows, u64 columns)
            : MatricView2<T>(gsl::as_multi_span(new T[rows * columns], gsl::dim(rows), gsl::dim(columns)))
        {}

        ~Matrix()
        {
            delete[] MatricView2<T>::data();
        }

        using MatricView2<T>::operator[];
        using MatricView2<T>::operator=;
        using MatricView2<T>::data;
        using MatricView2<T>::begin;
        using MatricView2<T>::end;
        using MatricView2<T>::bounds;

        using value_type = typename gsl::multi_span<T, gsl::dynamic_range, gsl::dynamic_range>::value_type;
        using pointer = typename MatricView2<T>::pointer;

        //operator MatricView2<T>()() const
        //{
        //    return mView;
        //}
    };

}
