import sys
if sys.version_info < (3, 0):
    sys.stdout.write("Sorry, requires Python 3.x, not Python 2.x\n")
    sys.exit(1)

import tarfile
import os 
import urllib.request
import platform


def getBoost():
    version = "75"
    folder = "boost_1_{0}_0".format(version)
    arch = "{0}.tar.bz2".format(folder)
    url = "https://boostorg.jfrog.io/artifactory/main/release/1.{0}.0/source/{1}".format(version, arch)


    


    if os.path.isdir("boost") == False:
        if not os.path.exists(arch):
            try:
                print("url: ", url)
                print("downloading boost...")
                urllib.request.urlretrieve(url, arch)
            except:
                cwd = os.getcwd()
                print("failed to download boost. please manually download the archive to")
                print("{0}/{1}".format(cwd, arch))

        print("extracting boost...")
        tar = tarfile.open(arch, 'r:bz2')
        tar.extractall()
        tar.close()
        os.remove(arch)
        os.rename(folder, "boost")

    

    osStr = (platform.system())
    if(osStr == "Windows"):


        preamble = r"\"\"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat\"\"" +"\n" + \
            "cd boost\n"

        cmd0 = preamble + \
            "bootstrap.bat"
        cmd1 = preamble + \
            "b2.exe  toolset=msvc-14.2 architecture=x86 address-model=64 --with-thread --with-system --with-filesystem --with-regex --with-date_time stage link=static variant=debug,release threading=multi"



        

        print("cmd0: {0}".format(cmd0))    
        with open("deleteMe.bat", "wt") as f:
            f.write(cmd0);
        os.system("deleteMe.bat")

        print("cmd1: {0}".format(cmd1))    
        with open("deleteMe.bat", "wt") as f:
            f.write(cmd1);
        os.system("deleteMe.bat")

        os.remove("deleteMe.bat")


    else:
        os.system("cd boost; bash bootstrap.sh")
        os.system("cd boost; ./b2 stage --with-system --with-thread --with-filesystem --with-atomic --with-regex")



if __name__ == "__main__":
    getBoost()

#if [ ! -d boost ]; then
#    wget -c 'https://dl.bintray.com/boostorg/release/1.75.0/source/#boost_1_75_0.tar.bz2' -O ./boost_1_75_0.tar.bz2
#    tar xfj boost_1_75_0.tar.bz2
#    mv boost_1_75_0 boost
#    rm  boost_1_75_0.tar.bz2
#fi
#
#cd ./boost
#if [ ! -d includes ]; then
#    ./bootstrap.sh
#    ./b2 stage --with-system --with-thread --with-filesystem --with-atomic #link=static -mt 
#fi