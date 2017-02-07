#pragma once
#include "cryptoTools/gsl/multi_span.h"
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{


    template<typename T>
    class MatrixSpan
    {
    protected:

        template <typename T>
        using __mspan = multi_span<T, dyn, dyn>;


        __mspan<T> mView;

    public:
        MatrixSpan()
        {}



        MatrixSpan(T* data, u64 rows, u64 columns) :
            mView(gsl::as_multi_span(new T[rows * columns](), gsl::dim(rows), gsl::dim(columns)))
        {}

        MatrixSpan(T* start, T* end, u64 columns) :
            mView(gsl::as_multi_span(&*start, gsl::dim((end - start) / columns), gsl::dim(columns)))
        {
        }


        // enabled if Iter is a random access iterator
        template <
            typename Iter,
            typename Dummy = std::enable_if_t<std::is_same<
                std::iterator_traits<Iter>::iterator_category,
                std::random_access_iterator_tag>::value>::type>
        MatrixSpan(Iter start, Iter end, u64 columns) :
            mView(gsl::as_multi_span(&*start, gsl::dim((end - start) / columns), gsl::dim(columns)))
        { }


        template<typename Container>
        using IteratorCategoryOf =
            typename std::iterator_traits<typename Container::iterator>::iterator_category;


        template<typename Container>
        using HaveRandomAccessIterator =
            std::is_base_of<
            std::random_access_iterator_tag,
            IteratorCategoryOf<Container>>;

        template<
            typename Container,
            typename Dummy = std::enable_if<HaveRandomAccessIterator<Container>::value>::type>
        MatrixSpan(const Container &c, u64 columns)
            : mView(gsl::as_multi_span(c.data(), sl::dim((c.end() - c.begin()) / columns), gsl::dim(columns)))
        {
        }




        using bounds_type = typename __mspan<T>::bounds_type;
        using size_type = typename __mspan<T>::size_type;
        using index_type = typename __mspan<T>::index_type;
        using value_type = typename __mspan<T>::value_type;
        using const_value_type = typename __mspan<T>::const_value_type;
        using pointer = typename __mspan<T>::pointer;
        using reference = typename __mspan<T>::reference;
        using iterator = typename __mspan<T>::iterator;
        using const_span = typename __mspan<T>::const_span;
        using const_iterator = typename __mspan<T>::const_iterator;
        using reverse_iterator = typename __mspan<T>::reverse_iterator;
        using const_reverse_iterator = typename __mspan<T>::const_reverse_iterator;
        using sliced_type = multi_span<value_type, dyn>;


        inline constexpr index_type bounds() const noexcept { return mView.bounds().index_bounds(); }
        inline constexpr size_type size() const noexcept { return mView.size(); }
        inline constexpr size_type size_bytes() const noexcept { return mView.size_bytes(); }

        inline constexpr pointer data() const noexcept { return mView.data(); }

        template <typename FirstIndex>
        inline constexpr reference operator()(FirstIndex index) { return mView(index); }

        template <typename FirstIndex, typename... OtherIndices>
        inline constexpr reference operator()(FirstIndex index, OtherIndices... indices) { return mView(index, indices); }

        inline constexpr reference operator[](const index_type& idx) const noexcept { return mView[idx]; }

        inline constexpr sliced_type operator[](size_type idx) const { return mView[idx]; }

        inline constexpr iterator begin() const noexcept { return mView.begin(); }

        inline constexpr iterator end() const noexcept { return mView.end(); }

        inline constexpr const_iterator cbegin() const noexcept { mView.cbegin(); }

        inline constexpr const_iterator cend() const noexcept { mView.cend(); }

        inline constexpr reverse_iterator rbegin() const noexcept { return  mView.rbegin(); }

        inline constexpr reverse_iterator rend() const noexcept { return mVIew.rend() }

        inline constexpr const_reverse_iterator crbegin() const noexcept { return mView.crbegin(); }

        inline constexpr const_reverse_iterator crend() const noexcept { return mView.crend(); }

        inline constexpr operator __mspan<T>()  noexcept { return mView; }
        inline constexpr __mspan<T> getView() const noexcept { return mView; }
    };



    template<typename T>
    class Matrix : public MatrixSpan<T>
    {

    public:
        Matrix()
        {}

        Matrix(u64 rows, u64 columns)
            : MatrixSpan<T>(new T[rows * columns](), rows, columns)
        {}

        ~Matrix()
        {
            delete[] mView.data();
        }



        void resize(u64 rows, u64 columns)
        {
            auto old = mView;

            mView = gsl::as_multi_span(new T[rows * columns](), gsl::dim(rows), gsl::dim(columns));

            auto min = std::min(old.size_bytes(), mView.size_bytes());
            memcpy(mView.data(), old.data(), min);

            delete[] old.data();
        }

    };


}
