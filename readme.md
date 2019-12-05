![](https://github.com/ladnir/cryptoTools/blob/master/title.PNG)
=====


CryptoTools is a portable c++14 library containing a collection of tools for building cryptographic protocols. This include asynchronous networking (Boost Asio), several fast primitives such as AES (AES-NI), Blake2, SHA1 (assembly), and eliptic curve crypto (miracl, Relic-Toolkit). There are also several other utilities tailered for implementing protocols.

Thirdparty networking is also supported. See `frontend_cryptoTools/tutorial/Network.cpp` for an example.
  

 
## Install
 
The library is *cross platform* and has been tested on both Windows, Linux and Mac. There are two library dependencies including [Boost 1.69](http://www.boost.org/) (networking), and two **optional dependencies** on, [Miracl](https://www.miracl.com/index), [Relic](https://github.com/relic-toolkit/relic/) for elliptic curves. The version of Miracl used by this library requires specific configuration and therefore we advise using the cloned repository that we provide. 
 
### Windows

In `Powershell`, this will set up the project 

```
git clone --recursive https://github.com/ladnir/cryptoTools
cd cryptoTools/thirdparty/win
getBoost.ps1; 
cd ../..
cryptoTools.sln
```

**Boost and visual studio 2017:**  If boost does not build with visual studio 2017 
follow [these instructions](https://stackoverflow.com/questions/41464356/build-boost-with-msvc-14-1-vs2017-rc). 

**Enabling Relic (for fast elliptic curves):**
 * Clone the Visual Studio port [Relic](https://github.com/ladnir/relic). 
 * Use the CMake command  `cmake . -DMULTI=OPENMP -DCMAKE_INSTALL_PREFIX:PATH=C:\libs  -DCMAKE_GENERATOR_PLATFORM=x64` generate a Visual Studio solution
 * Optional: Build with gmp/mpir for faster performance. 
 * Install it to `C:\libs` (build the `INSTALL` VS project).
 * Edit the config file [libOTe/cryptoTools/cryptoTools/Common/config.h](https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/config.h) to include `#define ENABLE_RELIC`.

**Enabling Miracl (for elliptic curves):**
 * `cd cryptoTools/thirdparty/win`
 * `getMiracl.ps1 ` (If the Miracl script fails to find visual studio 2017,  manually open and build the Miracl solution.)
 * `cd ../..`
 * Edit the config file [libOTe/cryptoTools/cryptoTools/Common/config.h](https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/config.h) to include `#define ENABLE_MIRACL`.

**IMPORTANT:**
 By default, the build system needs the NASM compiler to be located
at `C:\NASM\nasm.exe`. In the event that it isn't, there are two options, install it, 
or enable the pure c++ implementation:
 * Remove  `cryptoTools/Crypto/asm/sha_win64.asm` from the cryptoTools Project.
 * Edit the config file [libOTe/cryptoTools/cryptoTools/Common/config.h](https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/config.h) to remove `#define ENABLE_NASM`.

**Other options:**
 * The implementation of binary circuits in cryptoTools (`BetaCircuit`) can be enabled by edit the config file [libOTe/cryptoTools/cryptoTools/Common/config.h](https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/config.h) to include `#define ENABLE_CIRCUITS`.


**IMPORTANT:** By default, the build system needs the NASM compiler to be located
at `C:\NASM\nasm.exe`. In the event that it isn't, there are two options, install it, 
or enable the pure c++ implementation:
 * Remove  `cryptoTools/Crypto/asm/sha_win64.asm` from the cryptoTools Project.
 * Edit the config file [libOTe/cryptoTools/cryptoTools/Common/config.h](https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Common/config.h) to remove `#define ENABLE_NASM`.

 
Build the solution within visual studio or with `MSBuild`. To see all the command line options, execute the program 

`frontend.exe` 
  


 
 
### Linux
 
 In short, this will build the project (without elliptic curves)

```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe/cryptoTools/thirdparty/linux
bash boost.get
cd ../../..
make
```

This will build the minimum version of the library (wihtout elliptic curves). The libraries 
will be placed in `libOTe/lib` and the binary `frontend_libOTe` will be placed in 
`libOTe/bin` To see all the command line options, execute the program 
 
`./bin/frontend_libOTe`


**Enable elliptic curves using:**
 * `cmake .  -DENABLE_RELIC=ON`: Build the library with integration to the 
      [Relic](https://github.com/relic-toolkit/relic/) library. Requires that
      relic is built with `cmake . -DMULTI=OPENMP` and installed.
 * `cmake .  -DENABLE_MIRACL=ON`: Build the library with integration to the
     [Miracl](https://www.miracl.com/index) library. Requires building miracl 
 `   cd libOTe/cryptoTools/thirdparty/linux; bash miracl.get`.

**Other Options:**
 * `cmake .  -DENABLE_CIRCUITS=ON`: Build the library with the circuit library enabled.
 * `cmake .  -DENABLE_NASM=ON`: Build the library with the assembly base SHA1 implementation. Requires the NASM compiler.
 


**Note:** In the case that miracl or boost is already installed, the steps 
`cd cryptoTools/thirdparty/linux; bash boost.get` can be skipped and CMake will attempt 
to find them instead. Boost is found with the CMake findBoost package and miracl
is found with the `find_library(miracl)` command.
 


 ## License
 
This project has been placed in the public domain. As such, you are unrestricted in how you use it, commercial or otherwise. However, no warranty of fitness is provided. If you found this project helpful, feel free to spread the word and cite us.
 
 
 
 
## Help
 
Contact Peter Rindal rindalp@oregonstate.edu for any assistance on building or running the library.
 
