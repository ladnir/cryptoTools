
import os 
import platform


def getRelic():
    
    cwd = os.getcwd()
    #thirdparty = os.path.dirname(os.path.realpath(__file__))
    
    if os.path.isdir("relic") == False:
        os.system("git clone https://github.com/relic-toolkit/relic.git")
        #os.system("git checkout e670262184f8dd16e69765446d159f1dbcc1ebdd")

    os.chdir(cwd + "/relic")
    buildDir = cwd + "/relic/build"
        
    config = ""
    argStr = "-DCMAKE_BUILD_TYPE=Release"

    osStr = (platform.system())
    sudo = ""
    if(osStr == "Windows"):
        argStr = argStr + " -DMULTI=MSVCTLS"
        argStr = argStr + " -DCMAKE_INSTALL_PREFIX:PATH=C:\libs"
        argStr = argStr + " -DWSIZE=32 ARCH=X86"
        config = " --config Release "
        buildDir = buildDir + "_win"
    else:
        argStr = argStr + " -DMULTI=PTHREAD "
        sudo = "sudo "
        buildDir = buildDir + "_linux"

        
    mkDirCmd = "mkdir -p {0}".format(buildDir); 
    CMakeCmd = "cmake -S . -B {0} {1}".format(buildDir, argStr)
    BuildCmd = "cmake --build {0} {1} --parallel ".format(buildDir, config)


    InstallCmd = "{0}cmake --install {1}".format(sudo, buildDir)

    
    

    print(mkDirCmd + "\n\n")
    os.system(mkDirCmd)
    print(CMakeCmd + "\n\n")
    os.system(CMakeCmd)
    print(BuildCmd + "\n\n")
    os.system(BuildCmd)
    
    print ("Installing relic: {0}".format(InstallCmd))
    os.system(InstallCmd)



if __name__ == "__main__":
    getRelic()
