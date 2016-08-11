/*
Copyright (c) 2016, Nettitude
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <Windows.h>
#include <winnt.h>
#include <conio.h>
#include <string>
#include <iostream>
#include "Loader.h"

typedef VOID(*TestFunction)();


int main(int argc, char** argv)
{

    LOADER_FUNCTION_TABLE funTab = { 0 };

    funTab.fnGetModuleHandleA = &GetModuleHandleA;
    funTab.fnGetProcAddress = &GetProcAddress;
    funTab.fnLoadLibraryA = &LoadLibraryA;
    funTab.fnVirtualAlloc = &VirtualAlloc;
    funTab.fnVirtualFree = &VirtualFree;

#if defined(_WIN64)
    funTab.fnRtlAddFunctionTable = &RtlAddFunctionTable;
#endif

    LOADED_MODULE loadedModule = { 0 };

#if defined(_DEBUG)
    std::string dllPath( BINARY_PATH "\\Debug" "\\TestDLL.dll" );
#elif defined(_RELEASE)
    std::string dllPath( BINARY_PATH "\\Release" "\\TestDLL.dll" );
#elif defined(_RELWITHDEBINFO)
    std::string dllPath( BINARY_PATH "\\RelWithDebInfo" "\\TestDLL.dll" );
#elif defined(_MINSIZEREL)
    std::string dllPath( BINARY_PATH "\\MinSizeRel" "\\TestDLL.dll" );
#endif

    //replace CMake forward slashes
    for (std::string::iterator ch = dllPath.begin(); ch != dllPath.end(); ++ch )
    {
        if (*ch == '/')
        {
            dllPath.replace(ch, ch + 1, 1, '\\');
        }
    }
    
    std::cout << "Load: " << dllPath << "..." << std::endl;

    HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwFileSize = GetFileSize(hFile, NULL);

        if (dwFileSize)
        {
            LPVOID pvData = HeapAlloc(GetProcessHeap(), 0, dwFileSize);

            if (pvData)
            {
                DWORD dwRead = 0;

                if (ReadFile(hFile, pvData, dwFileSize, &dwRead, NULL) && dwRead == dwFileSize)
                {
                    DWORD status = Loader_LoadFromBuffer(&funTab, pvData, dwFileSize, &loadedModule);

                    if (ERROR_SUCCESS == status)
                    {
                        std::cout << "Module loaded OK" << std::endl;

#if defined(_WIN64)
                        status = Loader_RegisterExceptionTable(&funTab, &loadedModule);

                        if (ERROR_SUCCESS == status )
                        {
                            std::cout << "Exception table registered OK" << std::endl;
                        }
                        else
                        {
                            std::cout << "Failed to register exception table, error:" << status << std::endl;
                        }
#endif                   
                    }
                    else
                    {
                        std::cout << "Failed to load module, error:" << status << std::endl;
                    }
                }
                else
                {
                    std::cout << "Failed to read file, error:" << GetLastError() << std::endl;
                }

                HeapFree(GetProcessHeap(), 0, pvData);
            }
            else
            {
                std::cout << "Failed, unable to allocate memory" << std::endl;
            }
        }
        else
        {
            std::cout << "Failed, file size is zero" << std::endl;
        }

        CloseHandle(hFile);
    }
    else
    {
        std::cout << "Failed to open file, error:" << GetLastError() << std::endl;
    }

    if (loadedModule.hModule &&
        loadedModule.pEntryPoint)
    {
        //call DLL Main
        loadedModule.pEntryPoint(loadedModule.hModule, DLL_PROCESS_ATTACH, NULL);


        //get by name
        TestFunction test0 = (TestFunction)Loader_GetProcAddress(&loadedModule, "TestFunction0");
        TestFunction test1 = (TestFunction)Loader_GetProcAddress(&loadedModule, "TestFunction1");
        TestFunction test2 = (TestFunction)Loader_GetProcAddress(&loadedModule, "TestFunction2");
        TestFunction test3 = (TestFunction)Loader_GetProcAddress(&loadedModule, "TestFunction3");
        TestFunction test4 = (TestFunction)Loader_GetProcAddress(&loadedModule, "TestFunction4");
        TestFunction test5 = (TestFunction)Loader_GetProcAddress(&loadedModule, "TestFunction5");
        TestFunction test6 = (TestFunction)Loader_GetProcAddress(&loadedModule, "TestFunction6");
        TestFunction test7 = (TestFunction)Loader_GetProcAddress(&loadedModule, "TestFunction7");
        //get by ordinal
        TestFunction test8 = (TestFunction)Loader_GetProcAddress(&loadedModule, (CONST CHAR*)0x9);
        TestFunction test9 = (TestFunction)Loader_GetProcAddress(&loadedModule, (CONST CHAR*)0xA );

        test0();
        test1();
        test2();
        test3();
        test4();
        test5();
        test6();
        test7();
        test8();
        test9();
    }

    std::cout << "Press a key..." << std::endl;

    while (!_kbhit())
    {
        Sleep(1);
    }

    return 0;
}