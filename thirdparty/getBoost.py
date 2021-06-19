import sys
import shutil
if sys.version_info < (3, 0):
    sys.stdout.write("Sorry, requires Python 3.x, not Python 2.x\n")
    sys.exit(1)

import tarfile
import os 
import urllib.request
import subprocess
import platform


def getBoost(install, prefix, par):
    version = "75"
    folder = "boost_1_{0}_0".format(version)
    arch = "{0}.tar.bz2".format(folder)
    url = "https://boostorg.jfrog.io/artifactory/main/release/1.{0}.0/source/{1}".format(version, arch)


    cwd = os.getcwd()
    


    if os.path.isdir("boost") == False:
        if not os.path.exists(arch):
            try:
                print("url: ", url)
                print("downloading boost...")
                urllib.request.urlretrieve(url, arch)
            except:
                print("failed to download boost. please manually download the archive to")
                print("{0}/{1}".format(cwd, arch))

        print("extracting boost...")
        tar = tarfile.open(arch, 'r:bz2')
        tar.extractall()
        tar.close()
        os.remove(arch)
        os.rename(folder, "boost")

    os.chdir(cwd+ "/boost")

    osStr = (platform.system())
    if(osStr == "Windows"):
        
        if not install and len(prefix) == 0:
            prefix = cwd + "/win"

        temp = "./buildboost_deleteMe.ps1"
        findvsPath = cwd + "/findvs.ps1"

        f2 = open(temp, 'w')
        f2.write("\n")
        b2Args =\
            "toolset=msvc-14.2 architecture=x86 address-model=64 --with-thread" +\
            " --with-system --with-filesystem --with-regex --with-date_time" +\
            " link=static variant=debug,release threading=multi "

        if par != 1:
            b2Args = "-j" + str(par) + " " + b2Args

        findvs = ". \"" + findvsPath +"\""
        cmd0 = "./bootstrap.bat"
        cmd1 = "./b2.exe " + b2Args + " install "
        if len(prefix) >0:
            cmd1 += " --prefix=" + prefix

        f2.write(findvs + "\n")
        f2.write(cmd0 + "\n")
        f2.write(cmd1 + "\n")
        f2.close()


        print("\n\n=========== getBoost.py ================")
        print(findvs)    
        print(cmd0)    
        print(cmd1)    
        print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n\n")

        p = subprocess.Popen(['powershell.exe', temp])
        p.communicate()

        os.remove(temp)


    else:
        
        sudo = ""
        if install and "--sudo" in sys.argv:
            sudo = "sudo "

            
        if not install and len(prefix) == 0:
            prefix = cwd + "/unix"

        b2Args = "--with-system --with-thread --with-filesystem --with-atomic --with-regex"

        if par != 1:
            b2Args = " -j" + str(par) + " " + b2Args


        cmd0 = "bash bootstrap.sh"
        cmd1 = "./b2 " + b2Args
        cmd2 = sudo+" ./b2 " + b2Args  +" install "
        if len(prefix) > 0:
            cmd2 += " --prefix=" + prefix;


        print("\n\n=========== getBoost.py ================")
        print(cmd0)
        if len(sudo):
            print(cmd1)
        print(cmd2)
        print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n\n")

        os.system(cmd0)
        # build boost without sudo
        if len(sudo):
            os.system(cmd1)
        os.system(cmd2)

        os.chdir(cwd)




if __name__ == "__main__":
    prefix = ""
    getBoost(False,prefix,1)