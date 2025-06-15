#ifndef MEM_H
#define MEM_H

#include "common_defines.h"
// #include <windows.h>
// #include <winternl.h>

// Wrapper for NtAllocateVirtualMemory
NTSTATUS alloc_memory(OUT PVOID* BaseAddress, IN SIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);

// Wrapper for NtProtectVirtualMemory
NTSTATUS protect_memory(IN PVOID BaseAddress, IN SIZE_T RegionSize, IN ULONG NewProtect, OUT PULONG OldProtect);

// Wrapper for NtFreeVirtualMemory
NTSTATUS free_memory(IN PVOID BaseAddress, IN SIZE_T RegionSize, IN ULONG FreeType);

#endif // MEM_H 