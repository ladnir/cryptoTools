$ErrorActionPreference = "Stop"

$MSBuild_14 = 'C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe'
$MSBuild_15 = 'C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe'

# Update this if needed
$MSBuild = $MSBuild_15
$git = 'git'


if(!(Test-Path $MSBuild))
{
    Write-Host "Could not find MSBuild as"
    Write-Host "     $MSBuild"
    Write-Host ""
    Write-Host "Please update its location in the script"

    exit
}
 
$startDir = $PWD
 
$folder =  "$PWD\miracl"
if(!(Test-Path $folder))
{

    
    & $git clone https://github.com/ladnir/miracl.git
     
}
else
{
    Write-Host "$folder already exists. Skipping dowload and extract."
}

cd $folder

& $MSBuild miracl.sln  /p:Configuration=Release /p:Platform=x64
& $MSBuild miracl.sln  /p:Configuration=Debug /p:Platform=x64

cd $startDir
