
import os 
import sys 
import platform


def getRelic(install, prefix, par):
    
    cwd = os.getcwd()
    #thirdparty = os.path.dirname(os.path.realpath(__file__))
    
    if os.path.isdir("relic") == False:
        os.system("git clone https://github.com/relic-toolkit/relic.git")

    os.chdir(cwd + "/relic")
    os.system("git checkout 3f616ad64c3e63039277b8c90915607b6a2c504c")

    buildDir = cwd + "/relic/build"
        
    config = ""
    argStr = "-DCMAKE_BUILD_TYPE=Release"
    
    osStr = (platform.system())
    sudo = ""
    if(osStr == "Windows"):
        argStr = argStr + " -DMULTI=OPENMP"
        config = " --config Release "
        buildDir = buildDir + "_win"

        if not install:
            prefix = cwd + "/win"
    else:
        argStr = argStr + " -DMULTI=PTHREAD "

        if install and "--sudo" in sys.argv:
            sudo = "sudo "

        buildDir = buildDir + "_linux"
        
        if not install:
            prefix = cwd + "/unix"


    
    parallel = ""
    if par != 1:
        parallel = "--parallel " + str(par)
        
    CMakeCmd = "cmake -S . -B {0} {1}".format(buildDir, argStr)
    BuildCmd = "cmake --build {0} {1} {2} ".format(buildDir, config, parallel)

    InstallCmd = "{0}cmake --install {1}".format(sudo, buildDir)
    if len(prefix):
        InstallCmd += " --prefix {0} ".format(prefix)
    
    print("\n\n=========== getRelic.py ================")
    print("mkdir "+ buildDir)
    print(CMakeCmd)
    print(BuildCmd)
    print(InstallCmd)
    print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n\n")

    if not os.path.exists(buildDir):
        os.mkdir(buildDir)

    os.system(CMakeCmd)
    os.system(BuildCmd)
    
    if len(sudo):
        print ("Installing relic: {0}".format(InstallCmd))

    os.system(InstallCmd)



if __name__ == "__main__":
    getRelic(False, "", 1)
