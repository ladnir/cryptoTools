#include "TestCollection.h"


#include <cryptoTools/Common/Log.h>
#include <iomanip>
namespace osuCrypto
{

    TestCollection globalTests;


    void TestCollection::add(std::string name, std::function<void()> fn)
    {
        mTests.push_back({ std::move(name), std::move(fn) });
    }
    bool TestCollection::runOne(uint64_t idx)
    {
        bool passed = false;
        int w = int(std::ceil(std::log10(mTests.size())));

        if (idx < mTests.size())
        {

            std::cout << std::setw(w) << idx << " - " << Color::Blue << mTests[idx].mName << ColorDefault << std::flush;

            auto start = std::chrono::high_resolution_clock::now();
            try
            {
                mTests[idx].mTest(); std::cout << Color::Green << "  Passed" << ColorDefault;
                passed = true;
            }
            catch (const std::exception& e)
            {
                std::cout << Color::Red << "Failed - " << e.what() << ColorDefault;
            }

            auto end = std::chrono::high_resolution_clock::now();

            uint64_t time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            std::cout << "   " << time << "ms" << std::endl;

        }

        return passed;
    }

    bool TestCollection::runAll()
    {
        bool passed = true;
        for (uint64_t i = 0; i < mTests.size(); ++i)
        {
            passed &= runOne(i);
        }

        return passed;
    }

    void TestCollection::list()
    {
        int w = int(std::ceil(std::log10(mTests.size())));
        for (uint64_t i = 0; i < mTests.size(); ++i)
        {
            std::cout << std::setw(w) << i << " - " << Color::Blue << mTests[i].mName << std::endl << ColorDefault;
        }
    }


    void TestCollection::operator+=(const TestCollection& t)
    {
        mTests.insert(mTests.end(), t.mTests.begin(), t.mTests.end());
    }
}