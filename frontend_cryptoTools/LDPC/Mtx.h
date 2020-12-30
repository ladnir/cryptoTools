#pragma once


#include <vector>
#include <array>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Matrix.h"
#include <cassert>
#include <algorithm>
#include <set>

#include <iostream>

namespace osuCrypto
{
    struct Point
    {
        u64 mRow, mCol;
    };

    class DenseMtx;

    class SparseMtx
    {
    public:

        class Row : public span<u64>
        {
        public:
            Row() = default;
            Row(const Row& r) = default;
            Row& operator=(const Row& r) = default;


            explicit Row(const span<u64>& r) { (span<u64>&)* this = r; }
            //Row& operator=(const span<u64>& r) { (span<u64>&)* this = r; return *this; }
        };
        class Col : public span<u64>
        {
        public:
            Col() = default;
            Col(const Col& r) = default;
            Col& operator=(const Col& r) = default;

            explicit Col(const span<u64>& r) { (span<u64>&)* this = r; }
            //Col& operator=(const span<u64>& r) { (span<u64>&)* this = r; return *this; }
        };

        class ConstRow : public span<const u64>
        {
        public:
            ConstRow() = default;
            ConstRow(const ConstRow&) = default;
            ConstRow(const Row& r) : span<const u64>(r) { };

            ConstRow& operator=(const ConstRow&) = default;
            ConstRow& operator=(const Row& r) { (span<const u64>&)* this = r; };
        };
        class ConstCol : public span<const u64>
        {
        public:
            ConstCol() = default;
            ConstCol(const ConstCol&) = default;
            ConstCol(const Col& r) : span<const u64>(r) { };

            ConstCol& operator=(const ConstCol&) = default;
            ConstCol& operator=(const Col& c) { (span<const u64>&)* this = c; };
        };

        SparseMtx() = default;
        SparseMtx(const SparseMtx&) = default;
        SparseMtx(SparseMtx&&) = default;
        SparseMtx& operator=(const SparseMtx&) = default;
        SparseMtx& operator=(SparseMtx&&) = default;


        SparseMtx(u64 rows, u64 cols, span<Point> points)
        {
            init(rows, cols, points);
        }

        std::vector<u64> mDataRow, mDataCol;

        std::vector<Row> mRows;
        std::vector<Col> mCols;


        u64 rows() const { return mRows.size(); }
        u64 cols() const { return mCols.size(); }

        Row& row(u64 i) { return mRows[i]; }
        Col& col(u64 i) { return mCols[i]; }

        ConstRow row(u64 i) const { return mRows[i]; }
        ConstCol col(u64 i) const { return mCols[i]; }



        void init(u64 rows, u64 cols, span<Point> points)
        {
            std::vector<u64> rowSizes(rows);
            std::vector<u64> colSizes(cols);

#ifndef NDEBUG
            std::set<std::pair<u64, u64>> set;
#endif // !NDEBUG

            for (u64 i = 0; i < points.size(); ++i)
            {
                ++rowSizes[points[i].mRow];
                ++colSizes[points[i].mCol];

#ifndef NDEBUG
                auto s = set.insert({ points[i].mRow , points[i].mCol });

                if (!s.second)
                    std::cout << "dup " << points[i].mRow << " " << points[i].mCol << std::endl;
                assert(s.second);
#endif
            }

            mRows.resize(rows);
            mCols.resize(cols);
            mDataRow.resize(points.size());
            mDataCol.resize(points.size());
            auto iter = mDataRow.data();
            for (u64 i = 0; i < rows; ++i)
            {
                mRows[i] = Row(span<u64>(iter, iter + rowSizes[i]));
                iter += rowSizes[i];
                rowSizes[i] = 0;
            }

            iter = mDataCol.data();
            for (u64 i = 0; i < cols; ++i)
            {
                mCols[i] = Col(span<u64>(iter, iter + colSizes[i]));
                iter += colSizes[i];
                colSizes[i] = 0;
            }

            for (u64 i = 0; i < points.size(); ++i)
            {
                auto r = points[i].mRow;
                auto c = points[i].mCol;
                auto j = rowSizes[r]++;
                mRows[r][j] = c;
                auto k = colSizes[c]++;
                mCols[c][k] = r;
            }

            for (u64 i = 0; i < rows; ++i)
            {
                std::sort(row(i).begin(), row(i).end());
            }
            for (u64 i = 0; i < cols; ++i)
            {
                std::sort(col(i).begin(), col(i).end());
            }


            for (u64 i = 0; i < points.size(); ++i)
            {
                auto row = mRows[points[i].mRow];
                auto col = mCols[points[i].mCol];
                assert(std::find(row.begin(), row.end(), points[i].mCol) != row.end());
                assert(std::find(col.begin(), col.end(), points[i].mRow) != col.end());
            }
        }

        bool isSet(u64 row, u64 col)
        {
            assert(row < rows());
            assert(col < cols());
            
            auto iter = std::lower_bound(
                mCols[col].begin(),
                mCols[col].end(),
                row);
            return iter != mCols[col].end() && *iter == row;
        }

        bool validate()
        {
            std::vector<span<u64>::iterator> colIters(cols());
            for (u64 i = 0; i < cols(); ++i)
            {
                colIters[i] = mCols[i].begin();
            }

            for (u64 i = 0; i < rows(); ++i)
            {
                if (!std::is_sorted(mRows[i].begin(), mRows[i].end()))
                    return false;

                for (auto cc : mRows[i])
                {
                    if (cc >= cols())
                        return false;
                    if (colIters[cc] == mCols[cc].end())
                        return false;

                    if (*colIters[cc] != i)
                        return false;

                    ++colIters[cc];
                }
            }

            return true;
        }

        SparseMtx block(u64 row, u64 col, u64 rowCount, u64 colCount)
        {
            SparseMtx R;

            auto rEnd = row + rowCount;
            auto cEnd = col + colCount;

            assert(rows() > row);
            assert(rows() >= rEnd);
            assert(cols() > col);
            assert(cols() >= cEnd);

            u64 total = 0;
            std::vector<std::array<span<u64>::iterator, 2>> rowIters(rEnd - row);
            std::vector<std::array<span<u64>::iterator, 2>> colIters(cEnd - col);

            for (u64 i = row, ii = 0; i < rEnd; ++i, ++ii)
            {
                auto& rowi = mRows[i];
                auto iter = std::lower_bound(rowi.begin(), rowi.end(), col);
                auto end = std::lower_bound(iter, rowi.end(), cEnd);

                rowIters[ii][0] = iter;
                rowIters[ii][1] = end;

                for (auto c : span<u64>(iter, end))
                {
                    assert(c < cols());
                    assert(c - col < colCount);
                }

                total += end - iter;
            }


            for (u64 i = col, ii = 0; i < cEnd; ++i, ++ii)
            {
                auto& coli = mCols[i];
                auto iter = std::lower_bound(coli.begin(), coli.end(), row);
                auto end = std::lower_bound(iter, coli.end(), rEnd);

                colIters[ii][0] = iter;
                colIters[ii][1] = end;


                for (auto r : span<u64>(iter, end))
                {
                    assert(r < rows());
                    assert(r - row < rowCount);
                }
            }

            R.mDataRow.resize(total);
            R.mDataCol.resize(total);

            R.mRows.resize(rEnd - row);
            R.mCols.resize(cEnd - col);

            auto iter = R.mDataRow.begin();
            for (u64 i = 0; i < rowIters.size(); ++i)
            {
                auto size = std::distance(rowIters[i][0], rowIters[i][1]);

                //std::transform(rowIters[i][0], rowIters[i][1], iter, [&](const auto& src) {return src - col; });

                for (u64 j = 0; j < size; ++j)
                {
                    auto& cc = *(rowIters[i][0] + j);
                    auto& dd = *(iter + j);
                    dd = cc - col;
                    assert(dd < colCount);
                }
                if(size)
                    R.mRows[i] = Row(span<u64>(&*iter, size));
                iter += size;
            }

            iter = R.mDataCol.begin();
            for (u64 i = 0; i < colIters.size(); ++i)
            {
                auto size = std::distance(colIters[i][0], colIters[i][1]);
                //std::transform(colIters[i][0], colIters[i][1], iter, [&](const auto& src) {return src - row; });

                for (u64 j = 0; j < size; ++j)
                {
                    auto rr = *(colIters[i][0] + j);
                    *(iter + j) =  rr - row;
                    assert(*(iter + j) < rowCount);
                }

                if (size)
                    R.mCols[i] = Col(span<u64>(&*iter, size));

                iter += size;
            }

            assert(R.validate());

            return R;
        }

        DenseMtx dense() const;

        std::vector<u8> mult(span<const u8> x) const
        {
            std::vector<u8> y(rows());
            multAdd(x, y);
            return y;
        }





        void multAdd(span<const u8> x, span<u8> y) const
        {
            assert(cols() == x.size());
            assert(y.size() == rows());
            for (u64 i = 0; i < rows(); ++i)
            {
                for (auto c : row(i))
                {
                    assert(c < cols());
                    y[i] ^= x[c];
                }
            }
        }

        std::vector<u8> operator*(span<const u8> x) const
        {
            return mult(x);
        }


        void mult(std::vector<u64>& dest, const ConstRow& src)
        {
            //assert(src.size() == rows());
            //assert(dest.size() == cols());

            assert(0);
            dest.clear();


            for (u64 i = 0; i < cols(); ++i)
            {
                u64 bit = 0;

                auto mIter = col(i).begin();
                auto mEnd = col(i).end();

                auto xIter = src.begin();
                auto xEnd = src.end();

                while (mIter != mEnd && xIter != xEnd)
                {
                    if (*mIter < *xIter)
                        ++mIter;
                    else if (*xIter < *mIter)
                        ++xIter;
                    else
                    {
                        bit ^= 1;
                        ++xIter;
                        ++mIter;
                    }
                }

                if (bit)
                    dest.push_back(i);
            }
        }

        void mult(std::vector<u64>& dest, const ConstCol& src)
        {
            //assert(src.size() == rows());
            //assert(dest.size() == cols());
            assert(0);
            dest.clear();


            for (u64 i = 0; i < cols(); ++i)
            {
                u64 bit = 0;

                auto mIter = row(i).begin();
                auto mEnd = row(i).end();

                auto xIter = src.begin();
                auto xEnd = src.end();

                while (mIter != mEnd && xIter != xEnd)
                {
                    if (*mIter < *xIter)
                        ++mIter;
                    else if (*xIter < *mIter)
                        ++xIter;
                    else
                    {
                        bit ^= 1;
                        ++xIter;
                        ++mIter;
                    }
                }

                if (bit)
                    dest.push_back(i);
            }
        }


        SparseMtx mult(const SparseMtx& X) const
        {
            assert(cols() == X.rows());



            //SparseMtx y;
            std::vector<Point> points;
            //std::vector<u64> res;
            for (u64 i = 0; i < rows(); ++i)
            {
                auto r = this->row(i);
                for (u64 j = 0; j < X.cols(); ++j)
                {
                    auto c = X.col(j);

                    u64 bit = 0;

                    span<const u64>::iterator mIter = r.begin();
                    span<const u64>::iterator mEnd = r.end();

                    span<const u64>::iterator xIter = c.begin();
                    span<const u64>::iterator xEnd = c.end();

                    while (mIter != mEnd && xIter != xEnd)
                    {
                        if (*mIter < *xIter)
                            ++mIter;
                        else if (*xIter < *mIter)
                            ++xIter;
                        else
                        {
                            bit ^= 1;
                            ++xIter;
                            ++mIter;
                        }
                    }

                    if (bit)
                    {
                        points.push_back({ i,j });
                    }
                }
            }

            return SparseMtx(rows(), X.cols(), points);
        }

        SparseMtx operator*(const SparseMtx& X) const
        {
            return mult(X);
        }


        SparseMtx operator+(const SparseMtx& X) const
        {
            return add(X);
        }


        bool operator==(const SparseMtx& X) const
        {
            return rows() == X.rows() &&
                cols() == X.cols() &&
                mDataCol.size() == X.mDataCol.size() &&
                mDataCol == X.mDataCol;
        }


        SparseMtx add(const SparseMtx& p) const
        {
            assert(rows() == p.rows());
            assert(cols() == p.cols());

            SparseMtx r;
            r.mDataCol.reserve(
                p.mDataCol.size() +
                mDataCol.size());

            r.mRows.resize(rows());
            r.mCols.resize(cols());

            u64 prev = 0;
            for (u64 i = 0; i < cols(); ++i)
            {
                auto c0 = col(i);
                auto c1 = p.col(i);

                auto b0 = c0.begin();
                auto b1 = c1.begin();
                auto e0 = c0.end();
                auto e1 = c1.end();

                // push the non-zero loctions in order.
                // skip when they are equal, i.e. 1+1=0
                while (b0 != e0 && b1 != e1)
                {
                    if (*b0 < *b1)
                        r.mDataCol.push_back(*b0++);
                    else if(*b0 > *b1)
                        r.mDataCol.push_back(*b1++);
                    else
                    {
                        ++b0;
                        ++b1;
                    }
                }

                // push any extra
                while (b0 != e0)
                    r.mDataCol.push_back(*b0++);
                while (b1 != e1)
                    r.mDataCol.push_back(*b1++);

                r.mCols[i] = Col(span<u64>(
                    r.mDataCol.begin() + prev,
                    r.mDataCol.end()));

                prev = r.mDataCol.size();
            }

            r.mDataRow.reserve(r.mDataCol.size());
            prev = 0;
            for (u64 i = 0; i < rows(); ++i)
            {
                auto c0 = row(i);
                auto c1 = p.row(i);

                auto b0 = c0.begin();
                auto b1 = c1.begin();
                auto e0 = c0.end();
                auto e1 = c1.end();

                while (b0 != e0 && b1 != e1)
                {
                    if (*b0 < *b1)
                        r.mDataRow.push_back(*b0++);
                    else if(*b0 > *b1)
                        r.mDataRow.push_back(*b1++);
                    else 
                    {
                        ++b0; ++b1;
                    }
                }

                while (b0 != e0)
                    r.mDataRow.push_back(*b0++);
                while (b1 != e1)
                    r.mDataRow.push_back(*b1++);

                r.mRows[i] = Row(span<u64>(
                    r.mDataRow.begin() + prev,
                    r.mDataRow.end()));

                prev = r.mDataRow.size();
            }

            return r;
        }

        SparseMtx& operator+=(const SparseMtx& p)
        {
            *this = add(p);
            return *this;
        }


        SparseMtx invert() const;


        std::vector<Point> points() const
        {
            std::vector<Point> p; p.reserve(mDataCol.size());
            for (u64 i = 0; i < rows(); ++i)
            {
                for (auto c : row(i))
                    p.push_back({ i,c });
            }

            return p;
        }
    };


    inline std::ostream& operator<<(std::ostream& o, const SparseMtx& H)
    {
        for (u64 i = 0; i < H.rows(); ++i)
        {
            auto row = H.row(i);
            for (u64 j = 0, jj = 0; j < H.cols(); ++j)
            {
                if (jj != row.size() && j == row[jj])
                {
                    o << Color::Green << "1 " << Color::Default;
                    ++jj;
                }
                else
                    o << "0 ";
            }
            o << "\n";
        }

        return o;
    }




    struct DenseMtx
    {
        // column major.
        Matrix<block> mData;
        u64 mRows;

        DenseMtx() = default;
        DenseMtx(const DenseMtx&) = default;
        DenseMtx(DenseMtx&&) = default;

        DenseMtx& operator=(const DenseMtx&) = default;
        DenseMtx& operator=(DenseMtx&&) = default;


        DenseMtx(u64 rows, u64 cols)
        {
            resize(rows, cols);
        }


        void resize(u64 rows, u64 cols)
        {
            mRows = rows;
            mData.resize(cols, (rows + 127) / 128);
        }


        u64 rows() const { return mRows; }
        u64 cols() const { return mData.rows(); }

        BitReference operator()(u64 row, u64 col) const
        {
            assert(row < rows());
            assert(col < cols());

            return BitReference((void*)&mData(col, 0), row);
        }

        bool operator==(const DenseMtx& m) const
        {
            return rows() == m.rows()
                && cols() == m.cols()
                && std::memcmp(mData.data(), m.mData.data(), mData.size() * sizeof(block)) == 0;
        }


        struct Row
        {
            u64 mIdx;
            DenseMtx& mMtx;


            void swap(Row& r)
            {
                assert(mMtx.cols() == r.mMtx.cols());

                for (u64 colIdx = 0; colIdx < mMtx.cols(); ++colIdx)
                {
                    u8 bit = r.mMtx(r.mIdx, colIdx);
                    r.mMtx(r.mIdx, colIdx) = mMtx(mIdx, colIdx);
                    mMtx(mIdx, colIdx) = bit;
                }
            }


            bool isZero() const
            {
                for (u64 colIdx = 0; colIdx < mMtx.cols(); ++colIdx)
                {
                    u8 bit = mMtx(mIdx, colIdx);
                    if (bit)
                        return false;
                }
                return true;
            }
        };

        Row row(u64 i) const
        {
            return Row{ i, (DenseMtx&)*this };
        }



        //struct Col
        //{
        //    u64 mIdx;
        //    Mtx& mMtx;
        //};

        //Col col(u64 i)
        //{
        //    return Col{ i, (Mtx&)*this };
        //}


        span<block> col(u64 i)
        {
            return mData[i];
        }
        span<const block> col(u64 i) const
        {
            return mData[i];
        }

        void setZero()
        {
            memset(mData.data(), 0, mData.size() * sizeof(block));
        }


        SparseMtx sparse() const
        {
            std::vector<Point> points;
            for (u64 i = 0; i < rows(); ++i)
            {
                for (u64 j = 0; j < cols(); ++j)
                {
                    if ((*this)(i, j))
                        points.push_back({ i,j });
                }
            }

            SparseMtx s;
            s.init(rows(), cols(), points);

            return s;
        }


        DenseMtx mult(DenseMtx& m)
        {
            assert(cols() == m.rows());

            DenseMtx ret(rows(), m.cols());


            for (u64 i = 0; i < ret.rows(); ++i)
            {
                for (u64 j = 0; j < ret.cols(); ++j)
                {
                    u8 v = 0;
                    for (u64 k = 0; k < cols(); ++k)
                    {
                        v = v ^ ((*this)(i, k) & m(k, j));
                    }

                    ret(i, j) = v;
                }
            }

            return ret;
        }
        DenseMtx add(DenseMtx& m)
        {
            assert(rows() == m.rows() && cols() == m.cols());

            auto ret = *this;
            for (u64 i = 0; i < mData.size(); ++i)
                ret.mData(i) = ret.mData(i) ^ m.mData(i);

            return  ret;
        }

        DenseMtx operator+(DenseMtx& m)
        {
            return add(m);
        }


        DenseMtx operator*(DenseMtx& m)
        {
            return mult(m);
        }

        static DenseMtx Identity(int n)
        {
            DenseMtx I(n, n);

            for (u64 i = 0; i < n; ++i)
                I(i, i) = 1;

            return I;
        }


        DenseMtx invert() const;
    };




    inline std::ostream& operator<<(std::ostream& o, const DenseMtx& H)
    {
        for (u64 i = 0; i < H.rows(); ++i)
        {
            for (u64 j = 0; j < H.cols(); ++j)
            {
                if (H(i,j))
                    o << Color::Green << "1 " << Color::Default;
                else
                    o << "0 ";
            }
            o << "\n";
        }

        return o;
    }


    inline DenseMtx DenseMtx::invert() const
    {
        assert(rows() == cols());

        auto mtx = *this;
        auto n = this->rows();

        auto Inv = Identity(n);

        for (u64 i = 0; i < n; ++i)
        {
            if (mtx(i, i) == 0)
            {
                for (u64 j = i + 1; j < n; ++j)
                {
                    if (mtx(j, i) == 1)
                    {
                        mtx.row(i).swap(mtx.row(j));
                        Inv.row(i).swap(Inv.row(j));
                        break;
                    }
                }

                if (mtx(i, i) == 0)
                {
                    //std::cout << mtx << std::endl;
                    return {};
                }
            }

            for (u64 j = 0; j < n; ++j)
            {
                if (j != i && mtx(j, i))
                {
                    for (u64 k = 0; k < n; ++k)
                    {
                        mtx(j, k) ^= mtx(i, k);
                        Inv(j, k) ^= Inv(i, k);
                    }
                }
            }

        }

        return Inv;

    }


    inline DenseMtx SparseMtx::dense() const
    {
        DenseMtx mtx(rows(), cols());

        for (u64 i = 0; i < rows(); ++i)
        {
            for (auto j : row(i))
                mtx(i, j) = 1;
        }

        return mtx;
    }

    inline SparseMtx SparseMtx::invert() const
    {
        auto d = dense();
        d = d.invert();
        return d.sparse();
    }








    namespace tests
    {
        void Mtx_add_test();
        void Mtx_mult_test();
        void Mtx_invert_test();
        void Mtx_block_test();
    }






}