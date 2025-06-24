#ifndef MANUAL_LOADER_H
#define MANUAL_LOADER_H

#include "common_defines.h"
#include "ntstructs.h"

// Forward declare context to avoid circular dependency
struct _RTLDR_CTX;

// Manual loading flags
#define MANUAL_LOAD_NONE                0x00000000
#define MANUAL_LOAD_BYPASS_CALLBACKS    0x00000001  // Bypass PsSetLoadImageNotifyRoutine
#define MANUAL_LOAD_NO_ENTRY            0x00000002  // Don't execute DllMain
#define MANUAL_LOAD_FROM_MEMORY         0x00000004  // Load from memory buffer
#define MANUAL_LOAD_UNBACKED_MEMORY     0x00000008  // Use private (unbacked) memory
#define MANUAL_LOAD_HIDE_MODULE         0x00000010  // Don't add to PEB module list

// Manual load context structure
typedef struct _MANUAL_LOAD_CONTEXT {
    PVOID BaseAddress;
    SIZE_T ImageSize;
    PVOID EntryPoint;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER Sections;
    WORD NumberOfSections;
    ULONG Flags;
    BOOL IsLoaded;
    UNICODE_STRING ModuleName;
} MANUAL_LOAD_CONTEXT, *PMANUAL_LOAD_CONTEXT;

// Function pointer types for manual loading
typedef NTSTATUS (*pfnManualLoadLibrary)(
    struct _RTLDR_CTX* ctx,
    PVOID buffer_or_path,
    PVOID* loaded_module,
    ULONG flags
);

typedef NTSTATUS (*pfnManualUnloadLibrary)(
    struct _RTLDR_CTX* ctx,
    PVOID loaded_module
);

typedef PVOID (*pfnManualGetProcAddress)(
    struct _RTLDR_CTX* ctx,
    PVOID module_base,
    PCHAR function_name
);

typedef NTSTATUS (*pfnBypassLoadCallbacks)(
    struct _RTLDR_CTX* ctx,
    PVOID* memory_address,
    SIZE_T* memory_size,
    ULONG protection
);

// Manual loading strategy structure
typedef struct _MANUAL_LOAD_STRATEGY {
    // Strategy metadata
    const char* szStrategyName;
    DWORD dwVersion;
    
    // Core function pointers
    pfnManualLoadLibrary     pfnManualLoadLibrary;
    pfnManualUnloadLibrary   pfnManualUnloadLibrary;
    pfnManualGetProcAddress  pfnManualGetProcAddress;
    pfnBypassLoadCallbacks   pfnBypassLoadCallbacks;
} MANUAL_LOAD_STRATEGY, *PMANUAL_LOAD_STRATEGY;

// Core manual loading functions
NTSTATUS ManualLoadLibrary(
    struct _RTLDR_CTX* ctx,
    PVOID buffer_or_path,
    PVOID* loaded_module,
    ULONG flags
);

NTSTATUS ManualUnloadLibrary(
    struct _RTLDR_CTX* ctx,
    PVOID loaded_module
);

PVOID ManualGetProcAddress(
    struct _RTLDR_CTX* ctx,
    PVOID module_base,
    PCHAR function_name
);

NTSTATUS AllocateUnbackedMemory(
    struct _RTLDR_CTX* ctx,
    PVOID* memory_address,
    SIZE_T* memory_size,
    ULONG protection
);

// Utility functions
NTSTATUS ParsePEHeaders(
    PVOID image_base,
    PMANUAL_LOAD_CONTEXT load_ctx
);

NTSTATUS ProcessRelocations(
    struct _RTLDR_CTX* ctx,
    PMANUAL_LOAD_CONTEXT load_ctx,
    PVOID new_base
);

NTSTATUS ResolveImports(
    struct _RTLDR_CTX* ctx,
    PMANUAL_LOAD_CONTEXT load_ctx
);

NTSTATUS ApplySectionProtections(
    struct _RTLDR_CTX* ctx,
    PMANUAL_LOAD_CONTEXT load_ctx
);

// Strategy loader function
BOOL Strategy_LoadManualLoader(PMANUAL_LOAD_STRATEGY pStrategy);

#endif // MANUAL_LOADER_H 