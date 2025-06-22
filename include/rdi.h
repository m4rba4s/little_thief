#ifndef RDI_H
#define RDI_H

#include "common_defines.h"

// Forward declare the context structure to break circular dependency
struct _RTLDR_CTX;

// Main function to execute a reflective DLL from a memory buffer
NTSTATUS InvokeReflectiveLoader(
    struct _RTLDR_CTX* ctx,
    PVOID pReflectiveDllBuffer,
    const char* pszLoaderFuncName,
    LPVOID pParameter
);

#endif // RDI_H 