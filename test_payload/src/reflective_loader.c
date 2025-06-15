#include "../include/reflective_loader.h"
#include <intrin.h> // For __readgsqword on x64
// #include <windows.h>
// #include <winternl.h>

// Define PPEB if not already defined
#ifndef _PPEB_DEFINED
#define _PPEB_DEFINED
typedef struct _PEB *PPEB;
#endif

// Define PLDR_DATA_TABLE_ENTRY if not already defined
#ifndef _PLDR_DATA_TABLE_ENTRY_DEFINED
#define _PLDR_DATA_TABLE_ENTRY_DEFINED
typedef struct _LDR_DATA_TABLE_ENTRY *PLDR_DATA_TABLE_ENTRY;
#endif

// Extended LDR_DATA_TABLE_ENTRY definition with BaseDllName
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;  // This is what we need!
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// Define function pointer types needed ONLY by the active ReflectiveLoader logic
typedef HMODULE (WINAPI *LOADLIBRARYA_T)(LPCSTR);
typedef FARPROC (WINAPI *GETPROCADDRESS_T)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *VIRTUALALLOC_T)(LPVOID, SIZE_T, DWORD, DWORD);
// typedef BOOL    (WINAPI *VIRTUALPROTECT_T)(LPVOID, SIZE_T, DWORD, PDWORD); // Not used by current ReflectiveLoader
typedef BOOL    (WINAPI *DLLMAIN_T)(HINSTANCE, DWORD, LPVOID);

// Helper to get module handle (case-insensitive LDR walk)
static inline HMODULE GetModuleHandleReplacement(LPCWSTR moduleName) {
    PPEB peb = NULL;
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    if (!peb || !peb->Ldr) return NULL;

    PLIST_ENTRY listHead = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY currentEntryLink = listHead->Flink;

    while (currentEntryLink != listHead) {
        PLDR_DATA_TABLE_ENTRY_FULL pLdrEntry = CONTAINING_RECORD(currentEntryLink, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);

        if (pLdrEntry->BaseDllName.Buffer != NULL && pLdrEntry->BaseDllName.Length > 0) {
            WCHAR* currentName = pLdrEntry->BaseDllName.Buffer;
            USHORT currentNameLenChars = pLdrEntry->BaseDllName.Length / sizeof(WCHAR);
            
            LPCWSTR pTarget = moduleName;
            USHORT targetNameLenChars = 0;
            while(pTarget[targetNameLenChars] != L'\0') targetNameLenChars++;

            if (currentNameLenChars == targetNameLenChars) {
                BOOL match = TRUE;
                for (USHORT i = 0; i < currentNameLenChars; ++i) {
                    WCHAR c1 = currentName[i];
                    WCHAR c2 = moduleName[i]; // Use moduleName directly here
                    // ToUpper inline
                    if (c1 >= L'a' && c1 <= L'z') c1 -= (L'a' - L'A');
                    if (c2 >= L'a' && c2 <= L'z') c2 -= (L'a' - L'A');
                    if (c1 != c2) {
                        match = FALSE;
                        break;
                    }
                }
                if (match) {
                    return (HMODULE)pLdrEntry->DllBase;
                }
            }
        }
        currentEntryLink = currentEntryLink->Flink;
    }
    return NULL;
}

// Helper to get export address from a module (case-sensitive)
static inline FARPROC GetProcAddressReplacement(HMODULE hModule, LPCSTR procName) {
    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) return NULL;

    DWORD* pNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
        LPCSTR currentExportName = (LPCSTR)((BYTE*)hModule + pNames[i]);
        
        LPCSTR targetName = procName;
        LPCSTR currentName = currentExportName;
        while(*currentName != 0 && *targetName != 0 && *currentName == *targetName) {
            currentName++;
            targetName++;
        }
        if (*currentName == 0 && *targetName == 0) { // Match
            return (FARPROC)((BYTE*)hModule + pFunctions[pOrdinals[i]]);
        }
    }
    return NULL;
}

// The ReflectiveLoader function
__declspec(dllexport) LPVOID WINAPI ReflectiveLoader(LPVOID lpParameter) {
    LPBYTE pImageBase = (LPBYTE)lpParameter;
    if (!pImageBase) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    HMODULE hKernel32 = GetModuleHandleReplacement(L"KERNEL32.DLL");
    if (!hKernel32) return NULL;

    VIRTUALALLOC_T   pVirtualAlloc   = (VIRTUALALLOC_T)GetProcAddressReplacement(hKernel32, "VirtualAlloc");
    LOADLIBRARYA_T   pLoadLibraryA   = (LOADLIBRARYA_T)GetProcAddressReplacement(hKernel32, "LoadLibraryA");
    GETPROCADDRESS_T pGetProcAddress = (GETPROCADDRESS_T)GetProcAddressReplacement(hKernel32, "GetProcAddress");

    if (!pVirtualAlloc || !pLoadLibraryA || !pGetProcAddress) {
        return NULL; 
    }

    SIZE_T dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    LPBYTE pNewImageBase = (LPBYTE)pVirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pNewImageBase) {
        return NULL;
    }

    for(DWORD i=0; i < pNtHeaders->OptionalHeader.SizeOfHeaders; i++) {
        pNewImageBase[i] = pImageBase[i];
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        if (pSectionHeader[i].SizeOfRawData > 0) {
            LPBYTE pDest = pNewImageBase + pSectionHeader[i].VirtualAddress;
            LPBYTE pSrc = pImageBase + pSectionHeader[i].PointerToRawData;
            for(DWORD j=0; j < pSectionHeader[i].SizeOfRawData; j++) {
                pDest[j] = pSrc[j];
            }
        }
    }
    
    ULONG_PTR ulDelta = (ULONG_PTR)pNewImageBase - (ULONG_PTR)pNtHeaders->OptionalHeader.ImageBase;
    if (ulDelta != 0 && pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pNewImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        DWORD dwRelocSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        DWORD dwBytesProcessed = 0;

        while (dwBytesProcessed < dwRelocSize && pReloc->VirtualAddress != 0) {
            if (pReloc->SizeOfBlock == 0) break;

            PWORD pRelocData = (PWORD)((LPBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
            DWORD dwNumberOfEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            for (DWORD j = 0; j < dwNumberOfEntries; ++j) {
                WORD wTypeOffset = pRelocData[j];
                WORD wType = (wTypeOffset >> 12);
                WORD wOffset = (wTypeOffset & 0x0FFF);

                if (wType == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }
                
                PDWORD_PTR pdwPatchAddr = (PDWORD_PTR)(pNewImageBase + pReloc->VirtualAddress + wOffset);

                if (wType == IMAGE_REL_BASED_HIGHLOW) { 
                     *((DWORD*)pdwPatchAddr) += (DWORD)ulDelta;
                } else if (wType == IMAGE_REL_BASED_DIR64) { 
                     *pdwPatchAddr += ulDelta;
                }
            }
            dwBytesProcessed += pReloc->SizeOfBlock;
            pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloc + pReloc->SizeOfBlock);
        }
    }

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pNewImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        while (pImportDesc->Name != 0) {
            LPCSTR lpszDllName = (LPCSTR)(pNewImageBase + pImportDesc->Name);
            HMODULE hImportedModule = pLoadLibraryA(lpszDllName);

            if (hImportedModule) {
                PIMAGE_THUNK_DATA pOriginalFirstThunk = NULL;
                if(pImportDesc->OriginalFirstThunk) {
                    pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pNewImageBase + pImportDesc->OriginalFirstThunk);
                } else { 
                    pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pNewImageBase + pImportDesc->FirstThunk);
                }
                
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pNewImageBase + pImportDesc->FirstThunk);

                while (pOriginalFirstThunk->u1.AddressOfData != 0) {
                    FARPROC pfnImportedFunc = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
                        LPCSTR lpszProcOrdinal = (LPCSTR)IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal);
                        pfnImportedFunc = pGetProcAddress(hImportedModule, lpszProcOrdinal);
                    } else {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pNewImageBase + pOriginalFirstThunk->u1.AddressOfData);
                        LPCSTR lpszProcName = (LPCSTR)pImportByName->Name;
                        pfnImportedFunc = pGetProcAddress(hImportedModule, lpszProcName);
                    }
                    
                    pFirstThunk->u1.Function = (ULONG_PTR)pfnImportedFunc;

                    pOriginalFirstThunk++;
                    pFirstThunk++;
                }
            }
            pImportDesc++;
        }
    }

    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
        DLLMAIN_T pDllMain = (DLLMAIN_T)(pNewImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        if (pDllMain) {
            pDllMain((HINSTANCE)pNewImageBase, DLL_PROCESS_ATTACH, lpParameter); 
        }
    }
    return pNewImageBase;
}

// --- Helper Function Implementations (All removed as they are unused by the above ReflectiveLoader) ---
// GetKernel32Base, GetApiProcAddress, ResolveApiFunctions, r_wcsmpi, r_strcmp, GetBaseDllNameFromPath
// and their associated structures like API_FUNCTIONS and typedefs like LoadLibraryAFunc were here. 