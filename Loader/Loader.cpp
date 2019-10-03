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
#include "Loader.h"
#include <assert.h>

#if defined(_DEBUG)
#define DEBUG_ASSERT(X) assert((X))
#else
#define DEBUG_ASSERT(X) 
#endif


static DWORD GetDOSHeader(LPVOID pvData, DWORD cbSize, IMAGE_DOS_HEADER** pDOSHeader)
{
    DWORD dwStatus = ERROR_INVALID_PARAMETER;

    DEBUG_ASSERT(pDOSHeader);
    DEBUG_ASSERT(pvData);
    DEBUG_ASSERT(cbSize);

    if (pDOSHeader)
    {
        if (pvData &&
            cbSize > sizeof(IMAGE_DOS_HEADER))
        {
            *pDOSHeader = (IMAGE_DOS_HEADER*)pvData;

            if ((*pDOSHeader)->e_magic == IMAGE_DOS_SIGNATURE)
            {
                dwStatus = ERROR_SUCCESS;
            }
            else
            {
                dwStatus = ERROR_INVALID_MODULETYPE;
            }

        }
        else
        {
            dwStatus = ERROR_INVALID_DATA;
        }
    }

    return dwStatus;
}

static DWORD GetNTHeaders(LPVOID pvData, DWORD cbSize, IMAGE_NT_HEADERS** pNTHeader)
{
    DWORD dwStatus = ERROR_INVALID_PARAMETER;

    DEBUG_ASSERT(pNTHeader);
    DEBUG_ASSERT(pvData);
    DEBUG_ASSERT(cbSize);
    
    if (pNTHeader)
    {
        IMAGE_DOS_HEADER* pDOSHeader = NULL;
        dwStatus = GetDOSHeader(pvData, cbSize, &pDOSHeader);

        if (ERROR_SUCCESS == dwStatus)
        {
            CONST ULONGLONG REMAIN = cbSize - sizeof(IMAGE_DOS_HEADER)-sizeof(IMAGE_OPTIONAL_HEADER);

            if (pDOSHeader->e_lfanew < REMAIN)
            {
                *pNTHeader = (IMAGE_NT_HEADERS*)(((UINT_PTR)pDOSHeader) + pDOSHeader->e_lfanew);
                if ((*pNTHeader)->Signature == IMAGE_NT_SIGNATURE)
                {
                    dwStatus = ERROR_SUCCESS;
                }
                else
                {
                    dwStatus = ERROR_INVALID_MODULETYPE;
                }
            }
            else
            {
                dwStatus = ERROR_INVALID_DATA;
            }
        }
    }

    return dwStatus;
}


static BOOL IsOrdinal(UINT_PTR pvTest)
{   
    CONST UINT_PTR MASK = ~(UINT_PTR(0xFFFF));
    return (pvTest & MASK) == 0 ? TRUE : FALSE;
}

#define IS_ORDINAL(x) IsOrdinal((UINT_PTR)(x))

struct IMAGE_INFO
{
    static const DWORD IMAGE_FLAG_FILE = 1 << 0;

    IMAGE_INFO() : 
        ImageBase(NULL), 
        ImageDOSHeader(NULL),
        ImageNTHeaders(NULL), 
        Flags(0){}


    static DWORD Initialise(IMAGE_INFO& Image, LPVOID pvData, DWORD cbSize, DWORD dwFlags)
    {
        DEBUG_ASSERT(pvData);
        DEBUG_ASSERT(cbSize);

        DWORD dwStatus = ERROR_INVALID_PARAMETER;

        if (pvData)
        {
            Image.ImageBase = pvData;
            Image.Flags = dwFlags;
            Image.Size = cbSize;

            dwStatus = GetDOSHeader(pvData, cbSize, &Image.ImageDOSHeader);

            if (ERROR_SUCCESS == dwStatus)
            {
                dwStatus = GetNTHeaders(pvData, cbSize, &Image.ImageNTHeaders);
            }
        }

        return dwStatus;
    }

    LPVOID              ImageBase;
    PIMAGE_DOS_HEADER   ImageDOSHeader;
    PIMAGE_NT_HEADERS   ImageNTHeaders;
    DWORD               Flags;
    DWORD               Size;
};


struct RELOCATION
{
    WORD    Offset : 12;
    WORD    Type : 4;
};


struct ImageDirectory
{
    enum Enum
    {

        ENTRY_EXPORT                = IMAGE_DIRECTORY_ENTRY_EXPORT,        // Export Directory
        ENTRY_IMPORT                = IMAGE_DIRECTORY_ENTRY_IMPORT,        // Import Directory
        ENTRY_RESOURCE              = IMAGE_DIRECTORY_ENTRY_RESOURCE,      // Resource Directory
        ENTRY_EXCEPTION             = IMAGE_DIRECTORY_ENTRY_EXCEPTION,     // Exception Directory
        ENTRY_SECURITY              = IMAGE_DIRECTORY_ENTRY_SECURITY,      // Security Directory
        ENTRY_BASERELOC             = IMAGE_DIRECTORY_ENTRY_BASERELOC,     // Base Relocation Table
        ENTRY_DEBUG                 = IMAGE_DIRECTORY_ENTRY_DEBUG,         // Debug Directory
        ENTRY_ARCHITECTURE          = IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,  // Architecture Specific Data
        ENTRY_GLOBALPTR             = IMAGE_DIRECTORY_ENTRY_GLOBALPTR,     // RVA of GP
        ENTRY_TLS                   = IMAGE_DIRECTORY_ENTRY_TLS,           // TLS Directory
        ENTRY_LOAD_CONFIG           = IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,   // Load Configuration Directory
        ENTRY_BOUND_IMPORT          = IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,  // Bound Import Directory in headers
        ENTRY_IAT                   = IMAGE_DIRECTORY_ENTRY_IAT,           // Import Address Table
        ENTRY_DELAY_IMPORT          = IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,  // Delay Load Import Descriptors
        ENTRY_COM_DESCRIPTOR        = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,// COM Runtime descriptor
    };
};


static CONST IMAGE_SECTION_HEADER* ResolveVAToSection(IMAGE_INFO& Image,
                                                      UINT_PTR va )
{
    DEBUG_ASSERT(Image.ImageBase);
    DEBUG_ASSERT(Image.ImageNTHeaders);
    
    if (Image.ImageNTHeaders)
    {

        CONST IMAGE_SECTION_HEADER* pFirst = IMAGE_FIRST_SECTION(Image.ImageNTHeaders);

        if (pFirst)
        {
            for (DWORD dwCurrent = 0; dwCurrent < Image.ImageNTHeaders->FileHeader.NumberOfSections; ++dwCurrent)
            {
                CONST IMAGE_SECTION_HEADER* pCurrent = &pFirst[dwCurrent];

                if (va >= pCurrent->VirtualAddress &&
                    va < (pCurrent->VirtualAddress + pCurrent->Misc.VirtualSize))
                {
                    return pCurrent;
                }
            }
        }
    }

    return NULL;
}


template <typename T_Type>
__inline T_Type GetImageDirectory(IMAGE_INFO& Image,
                                  ImageDirectory::Enum Entry,
                                  CONST IMAGE_DATA_DIRECTORY** pOutDir = NULL )
{
    DEBUG_ASSERT(Image.ImageBase);
    DEBUG_ASSERT(Image.ImageNTHeaders);

    if (Image.ImageNTHeaders)
    {
        CONST IMAGE_DATA_DIRECTORY* pDir = &(Image.ImageNTHeaders->OptionalHeader.DataDirectory[Entry]);
        DEBUG_ASSERT(pDir);

        if (pDir)
        {
            if (pOutDir)
            {
                *pOutDir = pDir;
            }

            if (Image.Flags & IMAGE_INFO::IMAGE_FLAG_FILE)
            {
                CONST IMAGE_SECTION_HEADER* pSection = ResolveVAToSection(Image, pDir->VirtualAddress);

                if (pSection)
                {
                    //in a file we need to use the RVA
                    return reinterpret_cast<T_Type>((UINT_PTR)pSection->PointerToRawData + (UINT_PTR)Image.ImageBase);
                }
            }
            else if (pDir->Size &&
                pDir->VirtualAddress)
            {
                //the actual VA will be ok
                return reinterpret_cast<T_Type>((UINT_PTR)pDir->VirtualAddress + (UINT_PTR)Image.ImageBase);
            }
        }
    }

    return NULL;
}



//do not use for overlapped regions
static void Loader_CopyMemory(LPVOID pDest, LPCVOID pSrc, SIZE_T cbCopy)
{
    DEBUG_ASSERT(pDest);
    DEBUG_ASSERT(pSrc);
    DEBUG_ASSERT(cbCopy);

    if (pDest && pSrc && cbCopy)
    {
        while (cbCopy--)
            ((BYTE*)pDest)[cbCopy] = ((CONST BYTE*)pSrc)[cbCopy];
    }
}


static INT Loader_StrCmp(CONST CHAR* pSz1, CONST CHAR* pSz2)
{
    DEBUG_ASSERT(pSz1);
    DEBUG_ASSERT(pSz2);

    while (*pSz1 != 0)
    {
        if (*pSz2 == 0)
            return 1;

        if (*pSz2 > *pSz1)
            return -1;

        if (*pSz1 > *pSz2)
            return 1;

        ++pSz1;
        ++pSz2;
    }

    if (*pSz2 != 0)
        return -1;

    return 0;

}

extern "C" DWORD Loader_LoadFromBuffer(CONST LOADER_FUNCTION_TABLE* pFunTable,
    CONST LPVOID                 pBuffer,
    DWORD                        cbBuffer,
    LOADED_MODULE*               pResult)
{

    DEBUG_ASSERT(pFunTable);
    DEBUG_ASSERT(pFunTable->fnGetModuleHandleA);
    DEBUG_ASSERT(pFunTable->fnGetProcAddress);
    DEBUG_ASSERT(pFunTable->fnLoadLibraryA);
    DEBUG_ASSERT(pFunTable->fnVirtualAlloc);
    DEBUG_ASSERT(pFunTable->fnVirtualFree);

    DWORD dwStatus = ERROR_INVALID_PARAMETER;


    if (pFunTable &&
        pFunTable->fnGetModuleHandleA &&
        pFunTable->fnGetProcAddress &&
        pFunTable->fnLoadLibraryA &&
        pFunTable->fnVirtualAlloc &&
        pFunTable->fnVirtualFree)
    {

        if (pResult)
        {
            pResult->pNTHeaders = NULL;
            pResult->hModule = NULL;

            IMAGE_INFO RawImage;
            IMAGE_INFO LoadedImage;

            dwStatus = IMAGE_INFO::Initialise(RawImage, (LPVOID)pBuffer, cbBuffer, IMAGE_INFO::IMAGE_FLAG_FILE);

            if (ERROR_SUCCESS == dwStatus)
            {
                DWORD dwImageAllocationSize = RawImage.ImageNTHeaders->OptionalHeader.SizeOfImage;
                pResult->hModule = (HMODULE)pFunTable->fnVirtualAlloc( NULL,
                                                                       dwImageAllocationSize,
                                                                       MEM_RESERVE | MEM_COMMIT,
                                                                       PAGE_EXECUTE_READWRITE);

                if (pResult->hModule)
                {
                    dwStatus = ERROR_SUCCESS;

                    //Copy headers
                    Loader_CopyMemory(pResult->hModule,
                        pBuffer,
                        RawImage.ImageNTHeaders->OptionalHeader.SizeOfHeaders);

                    //Copy each section
                    CONST IMAGE_SECTION_HEADER* pFirst = IMAGE_FIRST_SECTION(RawImage.ImageNTHeaders);

                    if (pFirst)
                    {
                        CONST DWORD dwNumSection = RawImage.ImageNTHeaders->FileHeader.NumberOfSections;

                        DEBUG_ASSERT(RawImage.ImageNTHeaders->FileHeader.NumberOfSections);

                        if (RawImage.ImageNTHeaders->FileHeader.NumberOfSections)
                        {

                            for (DWORD dwCurrent = 0; dwCurrent < dwNumSection; ++dwCurrent)
                            {
                                CONST IMAGE_SECTION_HEADER* pCurrent = &pFirst[dwCurrent];
                                LPVOID pDest = (LPVOID)((UINT_PTR)pResult->hModule + pCurrent->VirtualAddress);
                                LPCVOID pSrc = (LPCVOID)((UINT_PTR)RawImage.ImageBase + pCurrent->PointerToRawData);

                                DWORD SectionSize = pCurrent->SizeOfRawData;

                                if (SectionSize == 0)
                                {
                                    if (pCurrent->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
                                    {
                                        SectionSize = RawImage.ImageNTHeaders->OptionalHeader.SizeOfInitializedData;
                                    }
                                    else if (pCurrent->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                                    {
                                        SectionSize = RawImage.ImageNTHeaders->OptionalHeader.SizeOfUninitializedData;
                                    }
                                    else
                                    {
                                        continue;
                                    }
                                }

                                Loader_CopyMemory(pDest,
                                    pSrc,
                                    SectionSize);

                            }
                        }
                        else
                        {
                            dwStatus = ERROR_INVALID_DATA;
                        }
                    }
                    else
                    {
                        dwStatus = ERROR_INVALID_DATA;
                    }

                    if (ERROR_SUCCESS == dwStatus)
                    {
                        //now use the mapped version
                        dwStatus = IMAGE_INFO::Initialise(LoadedImage, (LPVOID)pResult->hModule, dwImageAllocationSize, 0);

                        //Load imports
                        if (dwStatus == ERROR_SUCCESS)
                        {

                            CONST IMAGE_IMPORT_DESCRIPTOR* pDescriptor = GetImageDirectory< CONST IMAGE_IMPORT_DESCRIPTOR* >(LoadedImage, ImageDirectory::ENTRY_IMPORT);

                            if (pDescriptor)
                            {

                                //the final descriptor is a blank entry
                                while (pDescriptor->Name != NULL &&
                                    dwStatus == ERROR_SUCCESS)
                                {

                                    LPCSTR szLibraryName = (LPCSTR)((UINT_PTR)LoadedImage.ImageBase + pDescriptor->Name);
                                    HMODULE hLib = pFunTable->fnLoadLibraryA(szLibraryName);

                                    if (hLib)
                                    {
                                        PIMAGE_THUNK_DATA pThunk = NULL;
                                        PIMAGE_THUNK_DATA pAddrThunk = NULL;

                                        if (pDescriptor->OriginalFirstThunk)
                                        {
                                            pThunk = (PIMAGE_THUNK_DATA)((UINT_PTR)LoadedImage.ImageBase + pDescriptor->OriginalFirstThunk);
                                        }
                                        else
                                        {
                                            pThunk = (PIMAGE_THUNK_DATA)((UINT_PTR)LoadedImage.ImageBase + pDescriptor->FirstThunk);
                                        }

                                        pAddrThunk = (PIMAGE_THUNK_DATA)((UINT_PTR)LoadedImage.ImageBase + pDescriptor->FirstThunk);

                                        while (pAddrThunk &&
                                            pThunk &&
                                            pThunk->u1.AddressOfData &&
                                            dwStatus == ERROR_SUCCESS)
                                        {
                                            if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
                                            {
                                                LPCSTR Ordinal = (LPCSTR)IMAGE_ORDINAL(pAddrThunk->u1.Ordinal);
                                                pAddrThunk->u1.Function = (UINT_PTR)pFunTable->fnGetProcAddress(hLib, Ordinal);
                                            }
                                            else
                                            {
                                                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((UINT_PTR)LoadedImage.ImageBase + pThunk->u1.AddressOfData);
                                                pAddrThunk->u1.Function = (UINT_PTR)pFunTable->fnGetProcAddress(hLib, pImport->Name);
                                            }

                                            ++pThunk;
                                            ++pAddrThunk;
                                        }
                                    }
                                    else
                                    {
                                        dwStatus = ERROR_MOD_NOT_FOUND;
                                    }

                                    pDescriptor++;
                                }
                            }
                            else
                            {
                                dwStatus = ERROR_INVALID_DATA;
                            }
                        }
                    }

                    //fix up relocations
                    if (ERROR_SUCCESS == dwStatus)
                    {
                        CONST DWORD Size = LoadedImage.ImageNTHeaders->OptionalHeader.DataDirectory[ImageDirectory::ENTRY_BASERELOC].Size;

                        if (Size > 0)
                        {
                            CONST IMAGE_BASE_RELOCATION* pRelocTable = GetImageDirectory< CONST IMAGE_BASE_RELOCATION* >(LoadedImage, ImageDirectory::ENTRY_BASERELOC);

                            if (pRelocTable)
                            {
                                //last entry is empty
                                while (pRelocTable->SizeOfBlock)
                                {

                                    CONST DWORD CountRelocs = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCATION);

                                    if (CountRelocs)
                                    {
                                        //relocations follow the header
                                        RELOCATION* pReloc = (RELOCATION*)(pRelocTable + 1);
                                        CONST UINT_PTR Difference = ((UINT_PTR)LoadedImage.ImageBase - LoadedImage.ImageNTHeaders->OptionalHeader.ImageBase);

                                        for (DWORD dwCount = 0; dwCount < CountRelocs; ++dwCount)
                                        {
                                            UINT_PTR* pVal = (UINT_PTR*)((UINT_PTR)LoadedImage.ImageBase + pRelocTable->VirtualAddress + pReloc[dwCount].Offset);

                                            switch (pReloc[dwCount].Type)
                                            {
                                            case IMAGE_REL_BASED_DIR64:
                                            case IMAGE_REL_BASED_HIGHLOW:
                                                *pVal += Difference;
                                                break;
                                            case IMAGE_REL_BASED_HIGH:
                                                *pVal += HIWORD(Difference);
                                                break;
                                            case IMAGE_REL_BASED_LOW:
                                                *pVal += LOWORD(Difference);
                                                break;
                                            }
                                        }
                                    }

                                    //next block
                                    pRelocTable = (CONST IMAGE_BASE_RELOCATION*)(((UINT_PTR)pRelocTable) + pRelocTable->SizeOfBlock);
                                }
                            }
                            else
                            {
                                dwStatus = ERROR_INVALID_DATA;
                            }
                        }
                    }

                    if (dwStatus != ERROR_SUCCESS)
                    {
                        pFunTable->fnVirtualFree( LoadedImage.ImageBase,
                                                  dwImageAllocationSize,
                                                  MEM_RELEASE);

                        pResult->hModule = NULL;
                        pResult->pEntryPoint = NULL;
                        pResult->pNTHeaders = NULL;
                    }
                    else
                    {
                        pResult->pEntryPoint = (LOADER_FNDLLMAIN)((UINT_PTR)LoadedImage.ImageBase + LoadedImage.ImageNTHeaders->OptionalHeader.AddressOfEntryPoint);
                        pResult->pNTHeaders = LoadedImage.ImageNTHeaders;
                        pResult->dwSize = dwImageAllocationSize;
                    }
                }
            }
            else
            {
                dwStatus = ERROR_OUTOFMEMORY;
            }
        }
    }

    return dwStatus;
}


/*! \brief Similar to GetProcAddress in the Windows API
*/
extern "C" FARPROC Loader_GetProcAddress(CONST LOADED_MODULE* pModule, CONST CHAR* pszName)
{
    DEBUG_ASSERT(pModule);
    DEBUG_ASSERT(pModule->hModule);
    DEBUG_ASSERT(pszName);

    FARPROC pRet = NULL;

    if (pModule &&
        pszName &&
        pModule->hModule &&
        pModule->pNTHeaders )

    {
        if (pModule->pNTHeaders->OptionalHeader.NumberOfRvaAndSizes)
        {

            IMAGE_INFO Info;

            Info.ImageBase = pModule->hModule;
            Info.ImageNTHeaders = pModule->pNTHeaders;
            Info.Size = pModule->dwSize;

            CONST IMAGE_EXPORT_DIRECTORY* pExports = GetImageDirectory<CONST IMAGE_EXPORT_DIRECTORY*>(Info, ImageDirectory::ENTRY_EXPORT);

            if (pExports)
            {
                CONST DWORD INVALID_FUNCTION = DWORD(-1);

                PWORD pOrdinals = (PWORD)((UINT_PTR)pModule->hModule + pExports->AddressOfNameOrdinals);
                PDWORD pNames = (PDWORD)((UINT_PTR)pModule->hModule + pExports->AddressOfNames);
                DWORD functionIndex = INVALID_FUNCTION;

                if (IS_ORDINAL(pszName))
                {
                    DWORD ordinal = ((DWORD)pszName) - pExports->Base;

                    if (ordinal < pExports->NumberOfNames)
                    {
                        functionIndex = pOrdinals[ordinal];
                    }
                }
                else
                {
                    for (DWORD i = 0; i < pExports->NumberOfNames; ++i)
                    {
                        LPCSTR pszExpName = (LPCSTR)(((UINT_PTR)pModule->hModule + pNames[i]));
                        if (pszExpName && Loader_StrCmp(pszExpName, pszName) == 0)
                        {
                            functionIndex = pOrdinals[i];
                            break;
                        }
                    }
                }

                if (functionIndex != INVALID_FUNCTION)
                {
                    PDWORD pFuncs = (PDWORD)((UINT_PTR)pModule->hModule + pExports->AddressOfFunctions);

                    if (functionIndex < pExports->NumberOfFunctions)
                    {
                        pRet = (FARPROC)((UINT_PTR)pModule->hModule + pFuncs[functionIndex]);
                    }
                }
            }
        }
    }

    return pRet;
}

//64 bit only
#if defined(_WIN64)

extern "C" DWORD Loader_RegisterExceptionTable(CONST LOADER_FUNCTION_TABLE* pFunTable, CONST LOADED_MODULE* pModule)
{
    DWORD dwStatus = ERROR_INVALID_PARAMETER;

    DEBUG_ASSERT(pModule);
    DEBUG_ASSERT(pModule->dwSize);
    DEBUG_ASSERT(pModule->hModule);
    DEBUG_ASSERT(pFunTable);
    DEBUG_ASSERT(pFunTable->fnRtlAddFunctionTable);

    if (pFunTable &&
        pFunTable->fnRtlAddFunctionTable &&
        pModule &&
        pModule->hModule &&
        pModule->pNTHeaders &&
        pModule->dwSize )
    {
        IMAGE_INFO Info;

        Info.ImageBase = pModule->hModule;
        Info.ImageNTHeaders = pModule->pNTHeaders;
        Info.Size = pModule->dwSize;

        CONST IMAGE_DATA_DIRECTORY* pDir = NULL;
        CONST IMAGE_RUNTIME_FUNCTION_ENTRY* pExceptionDirectory = GetImageDirectory<CONST IMAGE_RUNTIME_FUNCTION_ENTRY*>(Info, ImageDirectory::ENTRY_EXCEPTION, &pDir);

        if (pExceptionDirectory)
        {
            CONST DWORD Count = (pDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1;
            
            if (Count)
            {

                if (pFunTable->fnRtlAddFunctionTable((CONST PRUNTIME_FUNCTION)pExceptionDirectory, Count, (DWORD64)pModule->hModule))
                {
                    dwStatus = ERROR_SUCCESS;
                }
                else
                {
                    dwStatus = S_FALSE;
                }
            }
            else
            {
                dwStatus = ERROR_SUCCESS;
            }
        }
        else
        {
            //no table
            dwStatus = ERROR_SUCCESS;
        }
    }

    return dwStatus;
}

#endif