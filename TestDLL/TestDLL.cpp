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

extern "C" VOID __declspec(dllexport) TestFunction0()
{
    MessageBoxA(NULL, "Hello from test function 0", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction1()
{
    MessageBoxA(NULL, "Hello from test function 1", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction2()
{
    MessageBoxA(NULL, "Hello from test function 2", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction3()
{
    MessageBoxA(NULL, "Hello from test function 3", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction4()
{
    MessageBoxA(NULL, "Hello from test function 4", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction5()
{
    MessageBoxA(NULL, "Hello from test function 5", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction6()
{
    MessageBoxA(NULL, "Hello from test function 6", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction7()
{
    MessageBoxA(NULL, "Hello from test function 7", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction8()
{
    MessageBoxA(NULL, "Hello from test function 8", "Hello", MB_OK);
}

extern "C" VOID __declspec(dllexport) TestFunction9()
{
    MessageBoxA(NULL, "Hello from test function 9", "Hello", MB_OK);
}


BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID)
{

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        MessageBoxA(NULL, "Hello from DllMain", "Hello", MB_OK);
    }
    break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    break;
    }

    return TRUE;
}