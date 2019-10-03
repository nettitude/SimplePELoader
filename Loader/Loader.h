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


/* 
   Very Simple PE Loader Library
   TOMW Nettitude 2016
*/

#ifndef __NETTTUDE_LOADER_H__
#define __NETTTUDE_LOADER_H__

#include <Windows.h>
#include <winternl.h>

#if defined __cplusplus
extern "C" {
#endif

    /* Function prototypes */
    typedef LPVOID  ( WINAPI *LOADER_FNVIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);     /* VirtuaAlloc */
    typedef BOOL    ( WINAPI *LOADER_FNVIRTUALFREE)(LPVOID, SIZE_T, DWORD);             /* VirtuaFree */
    typedef FARPROC ( WINAPI *LOADER_FNGETPROCADDRESS)(HMODULE, LPCSTR);                /* GetProcAddress */
    typedef HMODULE ( WINAPI *LOADER_FNGETMODULEHANDLEA)(LPCSTR);                       /* GetModuleHandleA */
    typedef HMODULE ( WINAPI *LOADER_FNLOADLIBRARYA)(LPCSTR);                           /* LoadLibraryA*/

#if defined(_WIN64)
    typedef BOOLEAN ( NTAPI *LOADER_RTLADDFUNCTIONTABLE)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress); /* RtlAddFunctionTable */
#endif

    /* Function table */
    typedef struct _LOADER_FUNCTION_TABLE
    {
        LOADER_FNVIRTUALALLOC       fnVirtualAlloc;
        LOADER_FNVIRTUALFREE        fnVirtualFree;

        LOADER_FNGETPROCADDRESS     fnGetProcAddress;
        LOADER_FNGETMODULEHANDLEA   fnGetModuleHandleA;
        LOADER_FNLOADLIBRARYA       fnLoadLibraryA;

#if defined(_WIN64)
        LOADER_RTLADDFUNCTIONTABLE  fnRtlAddFunctionTable;
#endif
    } LOADER_FUNCTION_TABLE, *PLOADER_FUNCTION_TABLE;

    typedef BOOL(WINAPI *LOADER_FNDLLMAIN)(HINSTANCE hModule, DWORD dwReason, LPVOID); /* DllMain */

    typedef struct _LOADED_MODULE
    {
        HMODULE                 hModule;
        LOADER_FNDLLMAIN        pEntryPoint;
        PIMAGE_NT_HEADERS       pNTHeaders;
        DWORD                   dwSize;
    }LOADED_MODULE, *PLOADED_MODULE;

    /*! \brief Load a DLL from the specified memory buffer
               The specified buffer can be released after
               the function returns

        \param pFunTable a populated loader function table
        \param pBuffer the buffer containing the DLL
        \param cbBuffer number of bytes in the buffer
        \param pResult pointer to result which is populated

        \returns a Windows error code or S_OK on success
     */

    DWORD Loader_LoadFromBuffer(
                                   CONST LOADER_FUNCTION_TABLE* pFunTable,
                                   CONST LPVOID                 pBuffer, 
                                   DWORD                        cbBuffer,
                                   LOADED_MODULE*               pResult
                               );

    /*! \brief Similar to GetProcAddress in the Windows API
    */
    FARPROC Loader_GetProcAddress
                               (
                                    CONST LOADED_MODULE* pModule, 
                                    CONST CHAR* pszName
                               );


#if defined(_WIN64)
    /*! \brief register the exception table */
    DWORD Loader_RegisterExceptionTable
                                (
                                    CONST LOADER_FUNCTION_TABLE* pFunTable,
                                    CONST LOADED_MODULE* pModule
                                );
#endif


#if defined __cplusplus
}
#endif

#endif //__NETTTUDE_LOADER_H__