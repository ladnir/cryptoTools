#pragma once
#include <vector>
#include <functional>
#include <string>
#include <cryptoTools/Common/Defines.h>

#define OSU_CRYPTO_PP_CAT(a, b) OSU_CRYPTO_PP_CAT_I(a, b)
#define OSU_CRYPTO_PP_CAT_I(a, b) OSU_CRYPTO_PP_CAT_II(~, a ## b)
#define OSU_CRYPTO_PP_CAT_II(p, res) res
#define OSU_CRYPTO_UNIQUE_NAME(base) OSU_CRYPTO_PP_CAT(base, __COUNTER__)


#define OSU_CRYPTO_ADD_TEST(harness, test)       \
static int OSU_CRYPTO_UNIQUE_NAME(__add_test_) = []() { \
    harness.add(STRINGIZE(test), test);          \
    return 0;                                    \
}();

namespace osuCrypto
{

    class TestCollection
    {
    public:
        struct Test
        {
            std::string mName;
            std::function<void()> mTest;
        };
        TestCollection() = default;
        TestCollection(std::function<void(TestCollection&)> init)
        {
            init(*this);
        }

        std::vector<Test> mTests;

        bool runOne(uint64_t);
        bool runAll();

        void list();

        void add(std::string name, std::function<void()> test);

        void operator+=(const TestCollection& add);
    };

    extern TestCollection globalTests;
}