
import os 
import sys 
import platform

import tarfile
import os 
import urllib.request
import subprocess
#ver = "1.0.18"
#folder = "libsodium-{0}".format(ver)
#tar = "{0}.tar.gz".format(folder)
#url = "https://download.libsodium.org/libsodium/releases/{0}".format(tar)
#arch = cwd +tar
#
#if os.path.isdir(folder) == False:
#    if not os.path.exists(arch):
#        try:
#            print("url: ", url)
#            print("downloading sodium...")
#            urllib.request.urlretrieve(url, arch)
#        except:
#            print("failed to download sodium. please manually download it")
#    print("extracting sodium...")
#    tar = tarfile.open(arch, 'r:gz')
#    tar.extractall()
#    tar.close()
#    os.remove(arch)
#
#os.chdir(cwd + folder)

def getSodium(install, prefix, par):
    
    cwd = os.getcwd() + "/"


    if os.path.isdir("libsodium") == False:
        os.system("git clone https://github.com/osu-crypto/libsodium.git")
    os.chdir("libsodium")

    argStr = ""
    
    osStr = (platform.system())
    sudo = ""
    if(osStr == "Windows"):
        findVS = "../findvs.ps1"
        temp = "./buildSodium_deleteMe.ps1"

        f1 = open(findVS, 'r')
        f2 = open(temp, 'w')
        # prepending the contents of findvs to our script
        f2.write(f1.read())
        f2.write("\n")
        
        #msvc version
        msvc = "v142"

        f2.write("MSBuild.exe ./libsodium.sln -t:libsodium -p:Configuration=Release /p:PlatformToolset={0}\n".format(msvc))
        
        f2.write('mkdir ../win/include/ -Force;')
        f2.write("mkdir ../win/lib/ -Force;")
        f2.write("cp ./src/libsodium/include/* ../win/include/ -Recurse -Force;")
        f2.write("cp ./Build/Release/x64/libsodium.lib ../win/lib/ -Force;")
        f2.close()

        p = subprocess.Popen(['powershell.exe', temp])
        p .communicate()

        os.remove(temp)
    else:

        # in case this is hosted in WSL
        os.system("find . -name \\*.m4|xargs dos2unix;")
        os.system("find . -name \\*.ac|xargs dos2unix")
        os.system("find . -name \\*.am|xargs dos2unix")
        os.system("./autogen.sh -s")

        if install and "--sudo" in sys.argv:
            sudo = "sudo "

        if not install:
            prefix = cwd + "/unix"

        if len(prefix):
            argStr += " --prefix=" + prefix
    
        parallel = ""
        if par != 1:
            parallel = "-j " + str(par)
        
        confgCmd = "./configure {0}".format(argStr)
        BuildCmd = "make {0} ".format(parallel)

        InstallCmd = "{0}make install".format(sudo)

        print(confgCmd + "\n\n")
        os.system(confgCmd)
        print(BuildCmd + "\n\n")
        os.system(BuildCmd)
    
        if len(sudo):
            print ("Installing sodium: {0}".format(InstallCmd))

        os.system(InstallCmd)



if __name__ == "__main__":
    getSodium(False, "", 1)
