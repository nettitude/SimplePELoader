@echo off
echo.
echo Generating x86...
echo.
@mkdir Build >nul
pushd Build
@mkdir win-build-x86 >nul
pushd win-build-x86
cmake ..\..\ -G "Visual Studio 12"
popd

echo.
echo Generating x64...
echo.

@mkdir win-build-x64 >nul
pushd win-build-x64
cmake ..\..\ -G "Visual Studio 12 Win64"
popd
popd