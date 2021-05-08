![](https://github.com/ladnir/cryptoTools/blob/master/title.PNG)
=====


CryptoTools is a portable c++14 library containing a collection of tools for building cryptographic protocols. This include asynchronous networking (Boost Asio), several fast primitives such as AES (AES-NI), Blake2 (assembly), and eliptic curve crypto (Relic-Toolkit, Miracl, or libsodium). There are also several other utilities tailored for implementing protocols.

Thirdparty networking is also supported. See `frontend_cryptoTools/tutorial/Network.cpp` for an example.
  

 
## Build
 
The library is *cross platform* and has been tested on both Windows, Linux and Mac. There are two **optional dependencies** including [Boost 1.69](http://www.boost.org/) (networking), and [Relic](https://github.com/relic-toolkit/relic/) for elliptic curves. 

 
 In short, this will build the project

```
git clone https://github.com/ladnir/cryptoTools
python build.py setup boost relic
python build.py -DENABLE_RELIC=ON 
```
The resulting binaries are written to `out/build/linux` or `out/build/x64-Release` depending on a unix or windows build. The frontend executable is `frontend_cryptoTools/`.

Relic and Boost are not required. In this case `boost`, `relic` can be omitted, e.g.
```
python build.py setup 
python build.py -DENABLE_RELIC=OFF -DENABLE_BOOST=OFF
```

Several other build options are available. See the output of `python build.py` or `cmake .`

 ## License
This project is dual licensed under MIT and Unlicensed.

For Unlicensed, this project has been placed in the public domain. As such, you are unrestricted in how you use it, 
commercial or otherwise. However, no warranty of fitness is provided. If you found this project 
helpful, feel free to spread the word and cite us.
 

 
 
 
## Help
 
Contact Peter Rindal peterrindal@gmail.com for any assistance on building or running the library.
 
