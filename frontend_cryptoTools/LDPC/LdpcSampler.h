#pragma once
#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <vector>
#include <numeric>

namespace osuCrypto
{

    inline void push(std::vector<Point>& p, Point x)
    {
        for (u64 i = 0; i < p.size(); ++i)
        {
            if (p[i].mCol == x.mCol && p[i].mRow == x.mRow)
            {
                assert(0);
            }
        }

        //std::cout << "{" << x.mRow << ", " << x.mCol << " } " << std::endl;
        p.push_back(x);
    }


    // samples a uniform partiy check matrix with
    // each column having weight w.
    inline void sampleFixedColWeight(u64 rows, u64 cols, u64 w, PRNG& prng, std::vector<Point>& points)
    {
        std::set<u64> set;
        for (u64 i = 0; i < cols; ++i)
        {
            set.clear();
            while(set.size() < w)
            {
                auto j = prng.get<u64>() % rows;
                if(set.insert(j).second)
                    push(points, { j, i });
            }
        }
    }

    // samples a uniform partiy check matrix with
    // each column having weight w.
    inline SparseMtx sampleFixedColWeight(u64 rows, u64 cols, u64 w, PRNG& prng)
    {
        std::vector<Point> points;
        sampleFixedColWeight(rows, cols, w, prng, points);
        return SparseMtx(rows, cols, points);
    }

    // samples a uniform set of size weight in the 
    // inteveral [begin, end). If diag, then begin 
    // will always be in the set.
    inline std::set<u64> sampleCol(u64 begin, u64 end, u64 weight, bool diag, PRNG& prng)
    {
        std::set<u64> idxs;

        auto n = end - begin;
        assert(n >= weight);

        if (diag)
        {
            idxs.insert(begin);
            ++begin;
            --n;
            --weight;
        }

        if (n < 3 * weight)
        {
            auto nn = std::min(3 * weight, n);
            std::vector<u64> set(nn);
            std::iota(set.begin(), set.end(), begin);

            std::shuffle(set.begin(), set.end(), prng);

            idxs.insert(set.begin(), set.begin() + weight);
        }
        else
        {
            while (idxs.size() < weight)
            {
                idxs.insert(prng.get<u64>() % n + begin);
            }
        }

        return idxs;
    }



    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline void sampleTriangular(u64 rows, u64 cols, u64 weight, u64 gap, PRNG& prng, std::vector<Point>& points)
    {
        auto b = cols - rows + gap;
        sampleFixedColWeight(rows, b, weight, prng, points);

        for (u64 i = 0; i < rows - gap; ++i)
        {
            auto w = std::min<u64>(weight - 1, (rows - i) / 2);
            auto s = sampleCol(i+1, rows, w, false, prng);

            push(points, { i, b + i });
            for (auto ss : s)
                push(points, { ss, b + i });

        }
    }



    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline void sampleTriangularBand(u64 rows, u64 cols, u64 weight, u64 gap, u64 dWeight, PRNG& prng, std::vector<Point>& points)
    {
        auto dHeight = gap + 1;
        assert(dWeight > 0);
        assert(dWeight <= dHeight);

        sampleFixedColWeight(rows, cols - rows, weight, prng, points);

        auto b = cols - rows;
        for (u64 i = 0, ii = rows - gap; i < rows; ++i, ++ii)
        {
            auto s = sampleCol(ii + 1, ii + dHeight, dWeight - 1, false, prng);

            push(points,{ ii % rows, b + i });
            for (auto ss : s)
                push(points,{ ss % rows, b + i });

        }
    }

    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline SparseMtx sampleTriangularBand(u64 rows, u64 cols, u64 weight, u64 gap, u64 dWeight, PRNG& prng)
    {
        std::vector<Point> points;
        sampleTriangularBand(rows, cols, weight, gap, dWeight, prng, points);
        return SparseMtx(rows, cols, points);
    }


    // sample a parity check which is approx triangular with. 
    // The other columns will have weight = weight.
    inline void sampleTriangular(u64 rows, double density, PRNG& prng, std::vector<Point>& points)
    {
        assert(density > 0);

        u64 t = ~u64{ 0 } * density;

        for (u64 i = 0; i < rows; ++i)
        {
            points.push_back({ i, i });

            for (u64 j = 0; j < i; ++j)
            {
                if (prng.get<u64>() < t)
                {
                    points.push_back({ i, j });
                }
            }
        }
    }

    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline SparseMtx sampleTriangular(u64 rows, double density, PRNG& prng)
    {
        std::vector<Point> points;
        sampleTriangular(rows, density, prng, points);
        return SparseMtx(rows, rows, points);
    }


    inline SparseMtx sampleTriangular(u64 rows, u64 cols, u64 weight, u64 gap, PRNG& prng)
    {
        std::vector<Point> points;
        sampleTriangular(rows, cols, weight, gap, prng, points);
        return SparseMtx(rows, cols, points);
    }

}