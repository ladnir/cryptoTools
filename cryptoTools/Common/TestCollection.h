#pragma once
#include <vector>
#include <functional>
#include <string>
#include <cryptoTools/Common/Defines.h>

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

        enum class Result
        {
            passed,
            skipped,
            failed
        };

        Result runOne(u64 idx);
        Result run(std::vector<u64> testIdxs, u64 repeatCount = 1);
        Result runAll(uint64_t repeatCount = 1);

        void list();

        void add(std::string name, std::function<void()> test);

        void operator+=(const TestCollection& add);
    };


    class UnitTestFail : public std::exception
    {
        std::string mWhat;
    public:
        explicit UnitTestFail(std::string reason)
            :std::exception(),
            mWhat(reason)
        {}

        explicit UnitTestFail()
            :std::exception(),
            mWhat("UnitTestFailed exception")
        {
        }

        virtual  const char* what() const throw()
        {
            return mWhat.c_str();
        }
    };

    class UnitTestSkipped : public std::runtime_error
    {
    public:
        UnitTestSkipped()
            : std::runtime_error("skipping test")
        {}

        UnitTestSkipped(std::string r)
            : std::runtime_error(r)
        {}
    };

    extern TestCollection globalTests;
}