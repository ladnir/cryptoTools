#include "CLP.h"
#include <sstream>
#include <iostream>


namespace osuCrypto
{

    void CLP::parse(int argc, char const*const* argv)
    {
        if (argc > 0)
        {
            std::stringstream ss;
            auto ptr = argv[0];
            while (*ptr != 0)
                ss << *ptr++;
            mProgramName = ss.str();
        }

        for (int i = 1; i < argc;)
        {
            auto ptr = argv[i];
            if (*ptr++ != '-')
            {
                throw CommandLineParserError();
            }

            std::stringstream ss;

            while (*ptr != 0)
                ss << *ptr++;

            ++i;
            ptr = argv[i];

            std::pair<std::string, std::list<std::string>> keyValues;
            keyValues.first = ss.str();;

            while (i < argc && (ptr[0] != '-' || (ptr[0] == '-' && ptr[1] >= '0' && ptr[1] <= '9')))
            {
                ss.str("");

                while (*ptr != 0)
                    ss << *ptr++;

                keyValues.second.push_back(ss.str());

                ++i;
                ptr = argv[i];
            }

            mKeyValues.emplace(keyValues);
        }
    }

    void CLP::setDefault(std::string key, std::string value)
    {
        if (hasValue(key) == false)
        {
            if (isSet(key))
            {
                mKeyValues[key].emplace_back(value);
            }
            else
            {
                mKeyValues.emplace(std::make_pair(key, std::list<std::string>{ value }));
            }
        }

    }
    void CLP::setDefault(std::vector<std::string> keys, std::string value)
    {
        if (hasValue(keys) == false)
        {
            setDefault(keys[0], value);
        }
    }

    bool CLP::isSet(std::string name)
    {
        return mKeyValues.find(name) != mKeyValues.end();
    }
    bool CLP::isSet(std::vector<std::string> names)
    {
        for (auto name : names)
        {
            if (isSet(name))
            {
                return true;
            }
        }
        return false;
    }

    bool CLP::hasValue(std::string name)
    {
        return mKeyValues.find(name) != mKeyValues.end() && mKeyValues[name].size();
    }
    bool CLP::hasValue(std::vector<std::string> names)
    {
        for (auto name : names)
        {
            if (hasValue(name))
            {
                return true;
            }
        }
        return false;
    }



    //
    //int CLP::getInt(std::vector<std::string> names, std::string failMessage)
    //{
    //    for (auto name : names)
    //    {
    //        if (hasValue(name))
    //        {
    //            return getInt(name);
    //        }
    //    }
    //
    //    if (failMessage != "")
    //        std::cout << failMessage << std::endl;
    //
    //    throw CommandLineParserError();
    //}
    //
    //double CLP::getDouble(std::string name)
    //{
    //    std::stringstream ss;
    //    ss << *mKeyValues[name].begin();
    //
    //    double ret;
    //    ss >> ret;
    //
    //    return ret;
    //}
    //
    //double CLP::getDouble(std::vector<std::string> names, std::string failMessage)
    //{
    //    for (auto name : names)
    //    {
    //        if (hasValue(name))
    //        {
    //            return getDouble(name);
    //        }
    //    }
    //
    //    if (failMessage != "")
    //        std::cout << failMessage << std::endl;
    //
    //    throw CommandLineParserError();
    //}
    //
    //std::string CLP::getString(std::string name)
    //{
    //    return *mKeyValues[name].begin();
    //}
    //
    //std::list<std::string> CLP::getStrings(std::string name)
    //{
    //    return mKeyValues[name];
    //}
    //
    //std::list<std::string> CLP::getStrings(std::vector<std::string> names, std::string failMessage)
    //{
    //    for (auto name : names)
    //    {
    //        if (hasValue(name))
    //        {
    //            return getStrings(name);
    //        }
    //    }
    //
    //    if (failMessage != "")
    //        std::cout << failMessage << std::endl;
    //
    //    throw CommandLineParserError();
    //}
    //
    //
    //std::string CLP::getString(std::vector<std::string> names, std::string failMessage)
    //{
    //    for (auto name : names)
    //    {
    //        if (hasValue(name))
    //        {
    //            return getString(name);
    //        }
    //    }
    //
    //    if (failMessage != "")
    //        std::cout << failMessage << std::endl;
    //
    //    throw CommandLineParserError();
    //}
    //
}
