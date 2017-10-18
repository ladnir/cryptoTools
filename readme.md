# CryptoTools 

CryptoTools is a portable c++14 library containing a collection of tools for building cryptographic protocols. This include asynchronous networking (Boost Asio), several fast primitives such as AES (AES-NI), SHA1 (assembly), and eliptic curve crypto (miracl). There are also several other utilities tailered for implementing protocols.


  

 
## Install
 
The library is *cross platform* and has been tested on both Windows and Linux. The library has worked on Mac but is not regularly tested. There are two library dependencies including [Boost](http://www.boost.org/) (networking), and [Miracl](https://www.miracl.com/index) (PK crypto). For each, we provide a script that automates the download and build steps. The version of Miracl used by this library requires specific configuration and therefore we advise using the cloned repository that we provide. 
 
### Windows

In `Powershell`, this will set up the project 

```
git clone --recursive https://github.com/ladnir/cryptoTools
cd cryptoTools/thirdparty/win
getBoost.ps1; getMiracl.ps1
cd ../..
cryptoTools.sln
```

Requirements: `Powershell`, Powershell `Set-ExecutionPolicy  Unrestricted`, `Visual Studio 2015`, CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`.
Optional: `nasm` for improved SHA1 performance. 
 
Build the solution within visual studio or with `MSBuild`. To see all the command line options, execute the program 

`frontend.exe` 
  


<b>IMPORTANT:</b> By default, the build system needs the NASM compiler to be located at `C:\NASM\nasm.exe`. In the event that it isn't, there are two options, install it, or enable the pure c++ implementation. The latter option is done by excluding `cryptoTools/Crypto/asm/sha_win64.asm` from the build system and undefining  `INTEL_ASM_SHA1` on line 28 of `cryptoTools/Crypto/sha1.cpp`.


 
 
### Linux
 
 In short, this will build the project

```
git clone --recursive https://github.com/ladnir/cryptoTools
cd cryptoTools/thirdparty/linux
bash all.get
cd ../..
cmake  .
make
```

Requirements: `CMake`, `Make`, `g++` or similar, CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`. Optional: `nasm` for improved SHA1 performance.

The libraries will be placed in `./lib` and the binary will be found at
 
`./bin/frontend_cryptoTools`

Note: In the case that miracl or boost is already installed, the steps  `cd cryptoTools/thirdparty/linux; bash all.get` can be skipped and CMake will attempt to find them instead. Boost is found with the CMake findBoost package and miracl is found with the `find_library(miracl)` command.
 

 ## License
 
This project has been placed in the public domain. As such, you are unrestricted in how you use it, commercial or otherwise. However, no warranty of fitness is provided. If you found this project helpful, feel free to spread the word and cite us.
 
 
 
 
## Help
 
Contact Peter Rindal rindalp@oregonstate.edu for any assistance on building or running the library.
 
