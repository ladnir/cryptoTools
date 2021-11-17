![](https://github.com/ladnir/cryptoTools/blob/master/title.PNG)
=====


CryptoTools is a portable c++14 library containing a collection of tools for building cryptographic protocols. This include asynchronous networking (Boost Asio), several fast primitives such as AES (AES-NI), Blake2 (assembly), and eliptic curve crypto (Relic-Toolkit, Miracl, or libsodium). There are also several other utilities tailored for implementing protocols.

Thirdparty networking is also supported. See `frontend_cryptoTools/tutorial/Network.cpp` for an example.
  

 

## Build
 
The library is *cross platform* and has been tested on Windows, Mac and Linux. 
There is one mandatory dependency on [Boost 1.75](http://www.boost.org/) (networking),
and **optional dependency** on
[Relic](https://github.com/relic-toolkit/relic). CMake 3.18+ is required and the build script assumes python 3.
 

```
git clone https://github.com/ladnir/cryptoTools
cd cryptoTools
python build.py --setup --boost --relic
python build.py -D ENABLE_RELIC=ON
```
It is possible to build only the protocol(s) that are desired via cmake command. In addition, if boost and or relic are already installed, then `boost` or `relic` can be ommitted from `python build.py setup boost relic`.

See the output of `python build.py` or `cmake .` for available compile options. For example, 
```
python build.py -D ENABLE_SSE=OFF
```
will build without SSE instrisics. Argument after the `--` are forwarded to cmake.

The main executable with examples is `frontend` and is located in the build directory, eg `out/build/linux/frontend/frontend_cryptoTools, out/build/x64-Release/frontend/Release/frontend_cryptoTools.exe` depending on the OS. 

**Enabling/Disabling dependancies:**
 * The library can be built without Relic as
```
python build.py --setup --boost
python build.py -D -D ENABLE_RELIC=OFF
```
 * The library can be built without Boost as
```
python build.py --setup --relic
python build.py -D -D ENABLE_BOOST=OFF
```
 

## Install

cryptoTools can be installed and linked the same way as other cmake project. By default the dependancies are not installed. To install then, run the following
```
python build.py --setup --boost --relic --install
```
You can also provide and install location by specifying `--install=path/to/installation`.

The main library is similarly installed as
```
python build.py --install 
```

By default, sudo is not used. If installation requires sudo access, then call
```
python build.py --install --sudo
```
See `python build.py --help` for full details.


## Linking
cryptoTools can be linked via cmake as
```
find_package(cryptoTools REQUIRED)

target_link_libraries(myProject oc::cryptoTools)
```
Other exposed targets are `oc::tests_cryptoTools`. In addition, cmake variables `cryptoTools_LIB, cryptoTools_INC, ENABLE_XXX` will be defined when found, where `XXX` is one of the cryptoTools options.

To ensure that cmake can find cryptoTools, you can either install cryptoTools or build it locally and include cryptoTools in the `CMAKE_PREFIX_PATH` variable or provide its location as a cmake `HINTS`.


 ## License
This project is dual licensed under MIT and Unlicensed.

For Unlicensed, this project has been placed in the public domain. As such, you are unrestricted in how you use it, 
commercial or otherwise. However, no warranty of fitness is provided. If you found this project 
helpful, feel free to spread the word and cite us.
 

 
 
 
## Help
 
Contact Peter Rindal peterrindal@gmail.com for any assistance on building or running the library.
 
