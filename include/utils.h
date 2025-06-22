#ifndef UTILS_H
#define UTILS_H

#include "common_defines.h"

// Forward declare the context structure to break circular dependency
struct _RTLDR_CTX;

// PEB/LDR structures are now included via common_defines.h -> windows.h -> winternl.h

// Function to find the base address of a loaded module in the current process
// Uses PEB/Ldr traversal
// HMODULE find_module_base(const wchar_t* module_name); // Duplicate, remove or consolidate

// Function to find the address of an exported function within a given module
// Parses the module's Export Address Table (EAT)
// FARPROC find_function(HMODULE module_base, const char* function_name); // Duplicate, remove or consolidate

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )

// Find the base address of a loaded module by its name hash (or name if no hash)
PVOID find_module_base(const WCHAR* module_name);

// Find the address of an exported function by its name hash (or name if no hash)
PVOID find_function(PVOID module_base, const char* function_name);

FARPROC FindExportedFunctionFromBuffer(PBYTE pImageBase, LPCSTR functionName);

// Reads a file into a newly allocated buffer using syscall wrappers.
// Caller is responsible for freeing ppPayloadBuffer using wrapped_NtFreeVirtualMemory.
BOOL ReadPayloadFileToMemory(struct _RTLDR_CTX* ctx, LPCWSTR pwszFileName, PBYTE* ppPayloadBuffer, PDWORD pdwPayloadSize);

#endif // UTILS_H 