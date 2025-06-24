#ifndef NTSTRUCTS_H
#define NTSTRUCTS_H

#include "common_defines.h"

// Extended LDR_DATA_TABLE_ENTRY with more fields than what's in winternl.h
typedef struct _LDR_DATA_TABLE_ENTRY_EX {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;  // This is what we need!
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_EX, *PLDR_DATA_TABLE_ENTRY_EX;

// File constants
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_GENERIC_READ
#define FILE_GENERIC_READ 0x120089
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ 0x00000001
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#endif

#ifndef FileStandardInformation
#define FileStandardInformation 5
#endif

#ifndef _FILE_STANDARD_INFORMATION_DEFINED
#define _FILE_STANDARD_INFORMATION_DEFINED
typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;
#endif

// Additional PE structures for manual loading
#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif

#ifndef IMAGE_FILE_MACHINE_I386
#define IMAGE_FILE_MACHINE_I386 0x014c
#endif

#ifndef IMAGE_REL_BASED_ABSOLUTE
#define IMAGE_REL_BASED_ABSOLUTE 0
#endif

#ifndef IMAGE_REL_BASED_HIGHLOW
#define IMAGE_REL_BASED_HIGHLOW 3
#endif

#ifndef IMAGE_REL_BASED_DIR64
#define IMAGE_REL_BASED_DIR64 10
#endif

#ifndef DLL_PROCESS_ATTACH
#define DLL_PROCESS_ATTACH 1
#endif

#ifndef IMAGE_SNAP_BY_ORDINAL
#define IMAGE_SNAP_BY_ORDINAL(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG) != 0)
#endif

#ifndef IMAGE_ORDINAL
#define IMAGE_ORDINAL(Ordinal) (Ordinal & 0xffff)
#endif

#ifndef IMAGE_ORDINAL_FLAG
#ifdef _WIN64
#define IMAGE_ORDINAL_FLAG 0x8000000000000000ULL
#else
#define IMAGE_ORDINAL_FLAG 0x80000000UL
#endif
#endif

#endif // NTSTRUCTS_H









