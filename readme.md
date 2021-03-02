![](https://github.com/ladnir/cryptoTools/blob/master/title.PNG)
=====


CryptoTools is a portable c++14 library containing a collection of tools for building cryptographic protocols. This include asynchronous networking (Boost Asio), several fast primitives such as AES (AES-NI), Blake2, SHA1 (assembly), and eliptic curve crypto (Relic-Toolkit). There are also several other utilities tailered for implementing protocols.

Thirdparty networking is also supported. See `frontend_cryptoTools/tutorial/Network.cpp` for an example.
  

 
## Install
 
The library is *cross platform* and has been tested on both Windows, Linux and Mac. There are two **optional dependencies** including [Boost 1.69](http://www.boost.org/) (networking), and [Relic](https://github.com/relic-toolkit/relic/) for elliptic curves. 

### Windows

In `Powershell`, this will set up the project 

```
git clone --recursive https://github.com/ladnir/cryptoTools
cd cryptoTools/thirdparty/win
[build boost at c:\libs\boost or thirdparty\win\boost]
cd ../..
cmake .
```

 * See `cmake .` for build options.

**Enable elliptic curves using:**
 * `cmake .  -DENABLE_RELIC=ON`: Build the library with integration to the 
      [Relic](https://github.com/relic-toolkit/relic/) library. Requires that
      relic is built with `cmake . -DMULTI=OPENMP` and installed.

**Boost and visual studio:**  If boost does not build with visual studio 2017+
follow [these instructions](https://stackoverflow.com/questions/41464356/build-boost-with-msvc-14-1-vs2017-rc). 

### Unix
 
 In short, this will build the project (without elliptic curves)

```
git clone --recursive https://github.com/ladnir/cryptoTools
cd thirdparty/linux
bash boost.get
cd ../..
make
```

This will build the minimum version of the library (wihtout elliptic curves).
 To see all the command line options, execute the program 
 
`./frontend_libOTe`


**Enable elliptic curves using:**
 * `cmake .  -DENABLE_RELIC=ON`: Build the library with integration to the 
      [Relic](https://github.com/relic-toolkit/relic/) library. Requires that
      relic is built with `cmake . -DMULTI=PTHREAD` and installed.

**Note:** In the case that miracl or boost is already installed, the steps 
`cd cryptoTools/thirdparty/linux; bash boost.get` can be skipped and CMake will attempt 
to find them instead. Boost is found with the CMake findBoost package. 


 ## License
This project is dual licensed under MIT and Unlicensed.

For Unlicensed, this project has been placed in the public domain. As such, you are unrestricted in how you use it, 
commercial or otherwise. However, no warranty of fitness is provided. If you found this project 
helpful, feel free to spread the word and cite us.
 

 
 
 
## Help
 
Contact Peter Rindal peterrindal@gmail.com for any assistance on building or running the library.
 
