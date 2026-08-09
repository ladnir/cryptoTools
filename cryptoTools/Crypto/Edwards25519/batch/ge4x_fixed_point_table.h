#pragma once

#include "ge4x.h"

#if defined(_MSC_VER)
#include <malloc.h>
#else
#include <cstdlib>
#endif
#include <new>

namespace osuCrypto
{
namespace details
{
    // Repeated multiplication of one four-lane broadcast point. Interleaving
    // four scalar windows reduces each multiplication from 252 doublings to
    // 12 while keeping the table small enough for the private caches.
    class Ge4xFixedPointTable
    {
    public:
        static constexpr int distance = 4;
        static constexpr int rows = 64 / distance;
        static constexpr int columns = 8;

        explicit Ge4xFixedPointTable(const ge25519& point)
            : mTable(allocate())
        {
            ge4x broadcast;
            ge4x_from_ge25519(&broadcast, &point);
            ge4x_maketable(table(), &broadcast, distance);
        }

        ~Ge4xFixedPointTable()
        {
#if defined(_MSC_VER)
            _aligned_free(mTable);
#else
            std::free(mTable);
#endif
        }

        Ge4xFixedPointTable(const Ge4xFixedPointTable&) = delete;
        Ge4xFixedPointTable& operator=(const Ge4xFixedPointTable&) = delete;

        void mul(ge4x& result, const sc25519 scalars[4]) const noexcept
        {
            ge4x_scalarsmults_table(
                &result, table(), scalars, distance);
        }

    private:
        static ge4x* allocate()
        {
            constexpr auto bytes = sizeof(ge4x) * rows * columns;
#if defined(_MSC_VER)
            auto* result = static_cast<ge4x*>(_aligned_malloc(bytes, 32));
            if (result == nullptr)
                throw std::bad_alloc();
            return result;
#else
            void* result = nullptr;
            if (posix_memalign(&result, 32, bytes) != 0)
                throw std::bad_alloc();
            return static_cast<ge4x*>(result);
#endif
        }

        ge4x (*table() noexcept)[columns]
        {
            return reinterpret_cast<ge4x (*)[columns]>(mTable);
        }

        const ge4x (*table() const noexcept)[columns]
        {
            return reinterpret_cast<const ge4x (*)[columns]>(mTable);
        }

        ge4x* mTable;
    };
}
}
