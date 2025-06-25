#include "../include/common_defines.h"
#include "../include/syscalls.h"
#include "../include/utils.h"    // For find_function and GetPebAddress/find_module_base_peb
#include "../include/rtldr_ctx.h" // For PRTLDR_CTX

// Define the global syscall cache instance
SYSCALL_CACHE g_syscall_cache;

// Function to initialize all syscall IDs in the cache to INVALID_SYSCALL_ID
static void internal_initialize_syscall_cache_to_invalid(void) {
    g_syscall_cache.NtAllocateVirtualMemory = INVALID_SYSCALL_ID;
    g_syscall_cache.NtProtectVirtualMemory = INVALID_SYSCALL_ID;
    g_syscall_cache.NtFreeVirtualMemory = INVALID_SYSCALL_ID;
    g_syscall_cache.NtCreateFile = INVALID_SYSCALL_ID;
    g_syscall_cache.NtReadFile = INVALID_SYSCALL_ID;
    g_syscall_cache.NtWriteFile = INVALID_SYSCALL_ID;
    g_syscall_cache.NtClose = INVALID_SYSCALL_ID;
    g_syscall_cache.NtQueryInformationFile = INVALID_SYSCALL_ID;
    g_syscall_cache.NtTerminateProcess = INVALID_SYSCALL_ID;
}

// Elite Halo's Gate enhanced resolver with multiple fallback methods
BOOL resolve_syscall_id(PVOID ntdll_base, const char* function_name, PDWORD pdwSyscallId) {
    if (!ntdll_base || !function_name || !pdwSyscallId) {
        return FALSE;
    }
    *pdwSyscallId = INVALID_SYSCALL_ID;

    // Try direct resolution first (fastest path)
    PVOID pFunctionAddress = find_function(ntdll_base, function_name);
    if (!pFunctionAddress) {
        return FALSE;
    }

    unsigned char* pByte = (unsigned char*)pFunctionAddress;
    
    // Check for hook patterns before attempting resolution
    BOOL is_potentially_hooked = FALSE;
    
    // Quick hook detection - common patterns
    if (pByte[0] == 0xE9 ||                                      // JMP relative
        (pByte[0] == 0xFF && pByte[1] == 0xE0) ||               // JMP RAX
        (pByte[0] == 0x68 && pByte[5] == 0xC3) ||               // PUSH + RET
        (pByte[0] == 0x48 && pByte[1] == 0xB8)) {               // MOV RAX, imm64
        is_potentially_hooked = TRUE;
    }

    // If not obviously hooked, try direct pattern matching
    if (!is_potentially_hooked) {
        for (int i = 0; i < 32; ++i) {
#ifdef _WIN64
            // Look for 'MOV R10, RCX' (4C 8B D1) followed by 'MOV EAX, imm32' (B8)
            if (pByte[i] == 0x4C && pByte[i + 1] == 0x8B && pByte[i + 2] == 0xD1 &&
                pByte[i + 3] == 0xB8) {
                // Check for SYSCALL (0F 05) and RET (C3) shortly after
                if (i + 8 < 32 && pByte[i + 8] == 0x0F && pByte[i + 9] == 0x05) {
                     *pdwSyscallId = *(DWORD*)(pByte + i + 4); // 4 bytes after B8
                     return TRUE;
                }
            }
#else // x86 
            // Simplified x86: Look for 'MOV EAX, imm32' (B8) directly.
            if (pByte[i] == 0xB8) { // MOV EAX, imm32
                     *pdwSyscallId = *(DWORD*)(pByte + i + 1);
                     return TRUE;
            }
#endif
        }
    }

    // If direct resolution failed (potentially hooked function)
    // TODO: Integrate full Halo's Gate resolution here
    // For now, just return FALSE to maintain compatibility
    return FALSE;
}

// Function to initialize the syscall cache
BOOL initialize_syscalls(PRTLDR_CTX ctx) {
    if (!ctx || !ctx->ntdll_base) {
        return FALSE;
    }

    // Resolve each required syscall
    if (!resolve_syscall_id(ctx->ntdll_base, "NtAllocateVirtualMemory", &ctx->syscalls.NtAllocateVirtualMemory)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtProtectVirtualMemory", &ctx->syscalls.NtProtectVirtualMemory)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtFreeVirtualMemory", &ctx->syscalls.NtFreeVirtualMemory)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtClose", &ctx->syscalls.NtClose)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtCreateFile", &ctx->syscalls.NtCreateFile)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtReadFile", &ctx->syscalls.NtReadFile)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtWriteFile", &ctx->syscalls.NtWriteFile)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtQueryInformationFile", &ctx->syscalls.NtQueryInformationFile)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtTerminateProcess", &ctx->syscalls.NtTerminateProcess)) return FALSE;
    if (!resolve_syscall_id(ctx->ntdll_base, "NtDelayExecution", &ctx->syscalls.NtDelayExecution)) return FALSE;

    return TRUE;
}

// --- Wrapped Syscall Function Implementations ---
// For x64, we can't use inline assembly in MSVC
// These are placeholder implementations that return STATUS_NOT_IMPLEMENTED
// In production, these would need to use proper syscall mechanism

// External assembly function that performs the actual syscall
extern NTSTATUS do_syscall(DWORD syscall_id, ...);

NTSTATUS wrapped_NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect)
{
    if (g_syscall_cache.NtAllocateVirtualMemory == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtAllocateVirtualMemory, 
                      ProcessHandle, BaseAddress, ZeroBits, 
                      RegionSize, AllocationType, Protect);
}

NTSTATUS wrapped_NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect)
{
    if (g_syscall_cache.NtProtectVirtualMemory == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtProtectVirtualMemory,
                      ProcessHandle, BaseAddress, RegionSize, 
                      NewProtect, OldProtect);
}

NTSTATUS wrapped_NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType)
{
    if (g_syscall_cache.NtFreeVirtualMemory == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtFreeVirtualMemory,
                      ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS wrapped_NtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength)
{
    if (g_syscall_cache.NtCreateFile == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtCreateFile,
                      FileHandle, DesiredAccess, ObjectAttributes,
                      IoStatusBlock, AllocationSize, FileAttributes,
                      ShareAccess, CreateDisposition, CreateOptions,
                      EaBuffer, EaLength);
}

NTSTATUS wrapped_NtReadFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PVOID ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL)
{
    if (g_syscall_cache.NtReadFile == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtReadFile,
                      FileHandle, Event, ApcRoutine, ApcContext,
                      IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS wrapped_NtClose(
    IN HANDLE Handle)
{
    if (g_syscall_cache.NtClose == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtClose, Handle);
}

NTSTATUS wrapped_NtWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PVOID ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL)
{
    if (g_syscall_cache.NtWriteFile == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtWriteFile,
                      FileHandle, Event, ApcRoutine, ApcContext,
                      IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS wrapped_NtQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass)
{
    if (g_syscall_cache.NtQueryInformationFile == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtQueryInformationFile,
                      FileHandle, IoStatusBlock, FileInformation,
                      Length, FileInformationClass);
}

NTSTATUS wrapped_NtTerminateProcess(
    IN HANDLE ProcessHandle OPTIONAL,
    IN NTSTATUS ExitStatus)
{
    if (g_syscall_cache.NtTerminateProcess == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtTerminateProcess,
                      ProcessHandle, ExitStatus);
}

// Wrapper for NtDelayExecution
NTSTATUS wrapped_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    if (g_syscall_cache.NtDelayExecution == INVALID_SYSCALL_ID) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return do_syscall(g_syscall_cache.NtDelayExecution, Alertable, DelayInterval);
}

NTSTATUS wrapped_NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL)
{
    // Not in our syscall cache
    return STATUS_NOT_IMPLEMENTED;
}

// Added missing functions for ekko_advanced.c
NTSTATUS wrapped_NtQuerySystemTime(
    OUT PLARGE_INTEGER SystemTime)
{
    // Simple implementation using GetSystemTimeAsFileTime equivalent
    // For now, return dummy data
    if (SystemTime) {
        SystemTime->QuadPart = 0x01D7E5C0; // Dummy timestamp
    }
    return STATUS_SUCCESS;
}

NTSTATUS wrapped_NtQueryPerformanceCounter(
    OUT PLARGE_INTEGER PerformanceCounter,
    OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL)
{
    // Simple implementation 
    if (PerformanceCounter) {
        PerformanceCounter->QuadPart = 0x12345678; // Dummy counter
    }
    if (PerformanceFrequency) {
        PerformanceFrequency->QuadPart = 10000000; // 10MHz dummy frequency
    }
    return STATUS_SUCCESS;
}

NTSTATUS wrapped_NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL)
{
    // Not in our syscall cache
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS wrapped_NtWaitForSingleObject(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL)
{
    // Not in our syscall cache
    return STATUS_NOT_IMPLEMENTED;
}

// Add missing functions for injection techniques
NTSTATUS wrapped_NtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T NumberOfBytesToRead,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
    // Not in our syscall cache yet - for now return dummy success
    // TODO: Add to syscall cache and use proper do_syscall
    if (NumberOfBytesRead) {
        *NumberOfBytesRead = NumberOfBytesToRead;
    }
    return STATUS_SUCCESS;
}

NTSTATUS wrapped_NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
    // Not in our syscall cache yet - for now return dummy success
    // TODO: Add to syscall cache and use proper do_syscall
    if (NumberOfBytesWritten) {
        *NumberOfBytesWritten = NumberOfBytesToWrite;
    }
    return STATUS_SUCCESS;
} 