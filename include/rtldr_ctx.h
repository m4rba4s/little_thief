#ifndef RTLDR_CTX_H
#define RTLDR_CTX_H

#include "common_defines.h" // Replaced <windows.h>

// This context structure is currently unused by the standard RDI implementation.
// It is defined as a placeholder for future extensions, such as:
// - Passing custom data to the payload.
// - Providing pointers to loader functions (e.g., custom GetProcAddress via syscalls)
//   if the ReflectiveLoader is modified to accept and use this context.

// Runtime Loader Context Structure
// This structure will hold important runtime data for the loader.
typedef struct _rtldr_ctx_t {
    PVOID ntdll_base;         // Base address of ntdll.dll
    BOOL  syscalls_initialized; // Flag to indicate if syscalls were resolved
    
    // TODO: Add more fields as the loader evolves:
    // - Handles to critical modules (kernel32, user32 etc. if resolved manually)
    // - Pointers to frequently used functions (if not using syscalls for everything)
    // - Configuration data passed to the loader
    // - Information about loaded payloads

} rtldr_ctx_t, *PRTLDR_CTX; // Added pointer type as per convention

#endif // RTLDR_CTX_H 