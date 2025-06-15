#include "../include/common_defines.h"
#include "../include/mem.h"
#include "../include/rtldr_ctx.h"
#include "../include/syscalls.h"

// Define NTSTATUS codes if not pulled in by standard headers (especially in no-CRT)
// #ifndef STATUS_SUCCESS
// #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
// #endif

// External definition of the assembly syscall stub
// The actual type should match the function pointer type expected by the wrapper
// extern NTSTATUS syscall_proxy(DWORD SyscallId, ...);

// --- Wrapper Implementations --- 

NTSTATUS alloc_memory(OUT PVOID* BaseAddress, IN SIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect) {
    // No longer need to resolve syscall ID here, it's handled in wrapped_NtAllocateVirtualMemory
    // SYSCALL_INFO info;
    // if (!resolve_syscall_id("NtAllocateVirtualMemory", &info)) {
    //    return (NTSTATUS)0xC0000001; 
    // }
    
    return wrapped_NtAllocateVirtualMemory(NtCurrentProcess(), BaseAddress, 0, &RegionSize, AllocationType, Protect);
}

NTSTATUS protect_memory(IN PVOID BaseAddress, IN SIZE_T RegionSize, IN ULONG NewProtect, OUT PULONG OldProtect) {
    // SYSCALL_INFO info;
    // if (!resolve_syscall_id("NtProtectVirtualMemory", &info)) {
    //     return (NTSTATUS)0xC0000001;
    // }

    return wrapped_NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, NewProtect, OldProtect);
}

NTSTATUS free_memory(IN PVOID BaseAddress, IN SIZE_T RegionSize, IN ULONG FreeType) {
    // SYSCALL_INFO info;
    SIZE_T size = (FreeType == MEM_RELEASE) ? 0 : RegionSize;
    PVOID address = BaseAddress; // NtFreeVirtualMemory expects PVOID*, but our wrapper takes PVOID
                               // The wrapper `wrapped_NtFreeVirtualMemory` needs to handle this adjustment if necessary
                               // or the assembly stub handles it. For now, assume PVOID is fine for the stub. 
                               // The original direct call was NtFreeVirtualMemory(NtCurrentProcess(), &address, &size, FreeType);
                               // Let's ensure our wrapped_NtFreeVirtualMemory matches that semantic. 
                               // The `wrapped_NtFreeVirtualMemory` takes PVOID* for BaseAddress. So &address is correct. 

    // if (!resolve_syscall_id("NtFreeVirtualMemory", &info)) {
    //     return (NTSTATUS)0xC0000001;
    // }

    return wrapped_NtFreeVirtualMemory(NtCurrentProcess(), &address, &size, FreeType);
}

// --- Syscall Proxy --- 
// This is the complex part: a C function that correctly sets up registers/stack
// and calls the assembly stub. This might involve inline assembly or a separate
// assembly function per wrapped NT function for type safety.

// Example using MSVC inline assembly (conceptual - needs correct implementation)
/*
__declspec(naked)
NTSTATUS syscall_proxy(DWORD SyscallId, ...) {
    // 1. Get arguments from stack/registers
    // 2. Move SyscallId into EAX
    // 3. Call the assembly stub (syscall_stub)
    // 4. Return value is in EAX
    __asm {
        mov eax, [esp+4] ; Get SyscallId (example, adjust based on calling convention)
        ; ... setup other arguments for syscall_stub ...
        call syscall_stub
        ret ; Return value is already in EAX
    }
}
*/ 

PVOID mem_alloc(PRTLDR_CTX ctx, SIZE_T size, DWORD protect) {
    PVOID base = NULL;
    NTSTATUS status = alloc_memory(&base, size, MEM_COMMIT | MEM_RESERVE, protect);
    if (NT_SUCCESS(status)) {
        return base;
    }
    return NULL;
} 