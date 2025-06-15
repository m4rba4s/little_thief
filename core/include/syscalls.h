#ifndef PHANTOM_EDGE_SYSCALLS_H
#define PHANTOM_EDGE_SYSCALLS_H

#include <windows.h>
#include <ntstatus.h> // For NTSTATUS and STATUS_SUCCESS etc.

#define INVALID_SYSCALL_ID 0xFFFFFFFF

// Structure to cache resolved syscall IDs
typedef struct _SYSCALL_CACHE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtCreateFile;
    DWORD NtReadFile;
    DWORD NtWriteFile;
    DWORD NtClose;
    DWORD NtQuerySystemInformation;
    DWORD NtCreateThreadEx;
    DWORD NtWaitForSingleObject;
    DWORD NtTerminateProcess;
    // Initialize all to INVALID_SYSCALL_ID in CoreLoaderMain or a dedicated init function
} SYSCALL_CACHE, *PSYSCALL_CACHE;

extern SYSCALL_CACHE g_syscall_cache; // Global instance

// Function to initialize the syscall cache
void initialize_syscall_cache(void);

// Function to resolve syscall ID by searching ntdll.dll for a specific function's syscall instruction
// Returns the syscall ID or INVALID_SYSCALL_ID if not found/error
DWORD resolve_syscall_id(const char* function_name);

// Naked function for the actual syscall invocation (ASM)
#ifdef _WIN64
extern void syscall_gate(void);
#else
// For x86, a different stub or approach would be needed.
// extern void syscall_stub_x86(void); // Placeholder
#endif

// --- Wrapped Syscall Functions ---
// These functions will use resolve_syscall_id and syscall_gate

NTSTATUS wrapped_NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

NTSTATUS wrapped_NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

NTSTATUS wrapped_NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
);

// Example for a file operation (signatures to be matched with ntdll)
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FilePositionInformation = 14,
    FileEndOfFileInformation = 20,
    // ... other values
} FILE_INFORMATION_CLASS;


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
    IN ULONG EaLength
);

NTSTATUS wrapped_NtReadFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PVOID ApcRoutine OPTIONAL, // PIO_APC_ROUTINE
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
);


NTSTATUS wrapped_NtWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PVOID ApcRoutine OPTIONAL, // PIO_APC_ROUTINE
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
);


NTSTATUS wrapped_NtClose(
    IN HANDLE Handle
);

// Add NtQuerySystemInformation if needed for unhooking or other purposes
// Example structure (simplified, check official headers for full definition)
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5, // For iterating processes
    SystemModuleInformation = 11  // For loaded modules (often used in unhooking)
    // ... other values
} SYSTEM_INFORMATION_CLASS;

NTSTATUS wrapped_NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);


NTSTATUS wrapped_NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList OPTIONAL // PPS_ATTRIBUTE_LIST
);

NTSTATUS wrapped_NtWaitForSingleObject(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL
);

NTSTATUS wrapped_NtTerminateProcess(
    IN HANDLE ProcessHandle OPTIONAL,
    IN NTSTATUS ExitStatus
);


#endif //PHANTOM_EDGE_SYSCALLS_H 