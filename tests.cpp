#include <iostream>
#include <cstdio>
#include <string>

#include <cryptoTools/Common/CuckooMap.h>
#include <cryptoTools/Common/Defines.h>

using namespace osuCrypto;

int main() {
    auto m = CuckooMap<std::string>(16);

    m[0] = "hello";

    printf("m[%d] = %s\n", 0, m[0].c_str());
}
