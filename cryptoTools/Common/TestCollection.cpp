#include "TestCollection.h"


#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/CLP.h>
#include <iomanip>
#include <cmath>
#include <algorithm>

namespace osuCrypto
{

    TestCollection globalTests;


    void TestCollection::add(std::string name, std::function<void(const CLP&)> fn)
    {
        mTests.push_back({ std::move(name), std::move(fn) });
    }
    void TestCollection::add(std::string name, std::function<void()> fn)
    {
        mTests.push_back({ std::move(name),[fn](const CLP& cmd)
        {
            fn();
        } });
    }

    TestCollection::Result TestCollection::runOne(uint64_t idx, CLP const * cmd)
    {
        if (idx >= mTests.size())
        {
            std::cout << Color::Red << "No test " << idx << std::endl;
            return Result::failed;
        }

        CLP dummy;
        if (cmd == nullptr)
            cmd = &dummy;

        Result res = Result::failed;
        int w = int(std::ceil(std::log10(mTests.size())));
        std::cout << std::setw(w) << idx << " - " << Color::Blue << mTests[idx].mName << ColorDefault << std::flush;

        auto start = std::chrono::high_resolution_clock::now();
        try
        {
            mTests[idx].mTest(*cmd); std::cout << Color::Green << "  Passed" << ColorDefault;
            res = Result::passed;
        }
        catch (const UnitTestSkipped& e)
        {
            std::cout << Color::Yellow << "  Skipped - " << e.what() << ColorDefault;
            res = Result::skipped;
        }
        catch (const std::exception& e)
        {
            std::cout << Color::Red << "Failed - " << e.what() << ColorDefault;
        }
        auto end = std::chrono::high_resolution_clock::now();



        uint64_t time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        std::cout << "   " << time << "ms" << std::endl;

        return res;
    }

    TestCollection::Result TestCollection::run(std::vector<u64> testIdxs, u64 repeatCount, CLP const * cmd)
    {
        u64 numPassed(0), total(0), numSkipped(0);

        for (u64 r = 0; r < repeatCount; ++r)
        {
            for (auto i : testIdxs)
            {
                if (repeatCount != 1) std::cout << r << " ";
                auto res = runOne(i, cmd);
                numPassed += (res == Result::passed);
                total += (res != Result::skipped);
                numSkipped += (res == Result::skipped);
            }
        }

        if (numPassed == total)
        {
            std::cout << Color::Green << std::endl
                << "=============================================\n"
                << "            All Passed (" << numPassed << ")\n";
            if(numSkipped)
                std::cout << Color::Yellow << "            skipped (" << numSkipped << ")\n";

            std::cout << Color::Green
                << "=============================================" << std::endl << ColorDefault;
            return Result::passed;
        }
        else
        {
            std::cout << Color::Red << std::endl
                << "#############################################\n"
                << "           Failed (" << total - numPassed << ")\n" << Color::Green
                << "           Passed (" << numPassed << ")\n";

            if (numSkipped)
                std::cout << Color::Yellow << "            skipped (" << numSkipped << ")\n";
            
            std::cout << Color::Red
                << "#############################################" << std::endl << ColorDefault;
            return Result::failed;
        }
    }

    std::vector<u64> TestCollection::search(const std::list<std::string>& s)
    {
        std::set<u64> ss;
        std::vector<u64> ret;
        std::vector<std::string> names;

        auto toLower = [](std::string data) {
            std::transform(data.begin(), data.end(), data.begin(),
                [](unsigned char c) { return std::tolower(c); });
            return data;
        };

        for (auto& t : mTests)
            names.push_back(toLower(t.mName));

        for (auto str : s)
        {
            auto lStr = toLower(str);
            for (auto& t : names)
            {
                if (t.find(lStr) != std::string::npos)
                {
                    auto i = &t - names.data();
                   if( ss.insert(i).second)
                       ret.push_back(i);
                }
            }
        }

        return ret;
    }

    TestCollection::Result TestCollection::runIf(CLP& cmd)
    {
        if (cmd.isSet("list"))
        {
            list();
            return Result::passed;
        }
        auto unitTestTag = std::vector<std::string>{ "u","unitTests" };
        if (cmd.isSet(unitTestTag))
        {
            cmd.setDefault("loop", 1);
            auto loop = cmd.get<u64>("loop");

            if (cmd.hasValue(unitTestTag))
            {
                auto& str = cmd.getList(unitTestTag);
                if (str.front().size() && std::isalpha(str.front()[0]))
                    return run(search(str), loop, &cmd);
                else
                    return run(cmd.getMany<u64>(unitTestTag), loop, &cmd);
            }
            else
                return runAll(loop, &cmd);
        }
        return Result::skipped;
    }

    TestCollection::Result TestCollection::runAll(uint64_t rp, CLP const * cmd)
    {
        std::vector<u64> v;
        for (u64 i = 0; i < mTests.size(); ++i)
            v.push_back(i);

        return run(v, rp, cmd);
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