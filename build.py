import os
import platform
import sys
from .thirdparty import getBoost
from .thirdparty import getRelic
#import thirdparty

def Setup():
	dir_path = os.path.dirname(os.path.realpath(__file__))
	os.chdir(dir_path + "/thirdparty")

	if "boost" in sys.argv:
		getBoost.getBoost()
	if "relic" in sys.argv:
		getRelic.getRelic()


def Build():

	osStr = (platform.system())
	buildDir = ""
	args = sys.argv[1:]
	config = ""
	buildType = ""
	if len(args) > 0 and args[0] == "Debug":
		buildType = "Debug"
		args = args[1:]
	else:
		buildType = "Release"


	if osStr == "Windows":
		buildDir = "out/build/x64-{0}".format(buildType)
		config = "--config {0}".format(buildType)
		args.append("-DCOMMON_FLAGS=/MP /Qpar")
	else:
		buildDir = "out/build/linux"


	args.append("-DCMAKE_BUILD_TYPE={0}".format(buildType))

	argStr = ""
	for a in args:
		argStr = argStr + " " + a

	mkDirCmd = "mkdir -p {0}".format(buildDir); 
	CMakeCmd = "cmake -S . -B {0} {1}".format(buildDir, argStr)
	BuildCmd = "cmake --build {0} {1} --parallel ".format(buildDir, config)

	print("Build Cmd:\n  {0}\n  {1}\n  {2}\n\n".format(mkDirCmd, CMakeCmd, BuildCmd))

	os.system(mkDirCmd)
	os.system(CMakeCmd)
	os.system(BuildCmd)


if __name__ == "__main__":
	if(len(sys.argv) > 1 and sys.argv[1] == "setup"):
		Setup()
	else:
		Build()
