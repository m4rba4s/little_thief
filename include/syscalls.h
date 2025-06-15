#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "common_defines.h"
#include "rtldr_ctx.h"

#define INVALID_SYSCALL_ID 0xFFFFFFFF // Define INVALID_SYSCALL_ID

// Structure to hold syscall information
typedef struct _SYSCALL_INFO {
    DWORD syscall_id;
    FARPROC function_address; // Keep original address for reference if needed
} SYSCALL_INFO, *PSYSCALL_INFO;

// Global syscall cache structure
// Ensure this matches the definition in syscalls.c
typedef struct _SYSCALL_CACHE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtCreateFile;
    DWORD NtReadFile;
    // DWORD NtWriteFile; // Add if/when wrapped_NtWriteFile is fully implemented and used
    DWORD NtClose;
    DWORD NtQueryInformationFile; // Added for ReadPayloadFileToMemory
    // DWORD NtQuerySystemInformation; // Add if/when wrapped_NtQuerySystemInformation is implemented
    // DWORD NtCreateThreadEx;       // Add if/when wrapped_NtCreateThreadEx is implemented
    // DWORD NtWaitForSingleObject;  // Add if/when wrapped_NtWaitForSingleObject is implemented
    DWORD NtTerminateProcess;     // For No-CRT exit
    // Add other syscall IDs here as they are implemented and cached
} SYSCALL_CACHE, *PSYSCALL_CACHE;

// External declaration for the assembly stub entry point
// Note: Its actual signature doesn't matter as we call it directly from asm
extern void syscall_stub(void);

// Remove duplicate definitions - they are already in winternl.h
// The guards we added don't work because winternl.h uses different guard names

/*
// Add missing structure definitions
#ifndef _IO_STATUS_BLOCK_DEFINED
#define _IO_STATUS_BLOCK_DEFINED
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
#endif

// Add missing FILE_INFORMATION_CLASS enum
#ifndef _FILE_INFORMATION_CLASS_DEFINED
#define _FILE_INFORMATION_CLASS_DEFINED
typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
#endif
*/

// Add FILE_STANDARD_INFORMATION structure
// #ifndef _FILE_STANDARD_INFORMATION_DEFINED
// #define _FILE_STANDARD_INFORMATION_DEFINED
// typedef struct _FILE_STANDARD_INFORMATION {
//     LARGE_INTEGER AllocationSize;
//     LARGE_INTEGER EndOfFile;
//     ULONG NumberOfLinks;
//     BOOLEAN DeletePending;
//     BOOLEAN Directory;
// } FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;
// #endif

// Add FileStandardInformation constant
#ifndef FileStandardInformation
#define FileStandardInformation 5
#endif

// Add missing file constants
#ifndef FILE_OPEN
#define FILE_OPEN                       0x00000001
#endif
#ifndef FILE_CREATE
#define FILE_CREATE                     0x00000002
#endif
#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF                    0x00000003
#endif
#ifndef FILE_OVERWRITE
#define FILE_OVERWRITE                  0x00000004
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF               0x00000005
#endif

// File create options
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE         0x00000040
#endif

// Add PIO_APC_ROUTINE typedef if missing
#ifndef _IO_APC_ROUTINE_DEFINED
#define _IO_APC_ROUTINE_DEFINED
typedef VOID (NTAPI *PIO_APC_ROUTINE)(
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
);
#endif

// Type definition for our specific syscall wrapper functions
typedef NTSTATUS (NTAPI* syscall_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);
typedef NTSTATUS (NTAPI* syscall_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);
typedef NTSTATUS (NTAPI* syscall_NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);
typedef NTSTATUS (NTAPI* syscall_NtClose)(
    HANDLE Handle
);
typedef NTSTATUS (NTAPI* syscall_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);
typedef NTSTATUS (NTAPI* syscall_NtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

// For getting file size
// typedef struct _FILE_STANDARD_INFORMATION { // This struct is defined in winternl.h (via windows.h)
//     LARGE_INTEGER AllocationSize;
//     LARGE_INTEGER EndOfFile;
//     ULONG         NumberOfLinks;
//     BOOLEAN       DeletePending;
//     BOOLEAN       Directory;
// } FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef NTSTATUS (NTAPI* syscall_NtQueryInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG/*FILE_INFORMATION_CLASS*/ FileInformationClass
);

// Add more types for NtCreateFile, NtReadFile etc. as needed

// Function pointer type for the assembly stub invoker
typedef NTSTATUS (NTAPI* syscall_invoker_func)(DWORD syscall_id, ...);

// Function to get a callable wrapper for a specific syscall
// This might return a pointer to a dynamically generated thunk or a pre-compiled one
syscall_invoker_func get_syscall_wrapper(const char* function_name);

// OR: Expose direct wrappers (Simpler for MVP)
NTSTATUS wrapped_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS wrapped_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
NTSTATUS wrapped_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
NTSTATUS wrapped_NtClose(HANDLE Handle);
NTSTATUS wrapped_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS wrapped_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
NTSTATUS wrapped_NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass);

// Function to resolve the syscall ID for a given NT function name
BOOL resolve_syscall_id(PVOID ntdll_base, const char* function_name, PDWORD pdwSyscallId);

// Function to initialize the syscall resolver (find ntdll base etc.)
BOOL initialize_syscalls(PRTLDR_CTX ctx);

// A generic syscall wrapper prototype (implementation will be complex)
// Using variadic functions or specific wrappers per function might be needed.
// For now, just a placeholder concept.
// NTSTATUS do_syscall(DWORD syscall_id, ...);

typedef NTSTATUS (NTAPI* syscall_NtTerminateProcess)(
    HANDLE ProcessHandle OPTIONAL,
    NTSTATUS ExitStatus
);

NTSTATUS wrapped_NtTerminateProcess(HANDLE ProcessHandle OPTIONAL, NTSTATUS ExitStatus);

#endif // SYSCALLS_H 