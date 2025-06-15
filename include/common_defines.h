#ifndef COMMON_DEFINES_H
#define COMMON_DEFINES_H

// 1. Define WIN32_LEAN_AND_MEAN first
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// 2. Explicitly define architecture macro if compiler doesn't expose it early enough
#if defined(_WIN64) && !defined(_AMD64_)
    #define _AMD64_
#elif defined(_WIN32) && !defined(_WIN64) && !defined(_X86_)
    #define _X86_
#endif

// 3. Define target Windows version
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06010000 // NTDDI_WIN7 (Windows 7)
#endif

// 4. Include windows.h with WIN32_NO_STATUS to avoid NTSTATUS conflicts
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

// 5. Include ntstatus.h for NTSTATUS codes
#include <ntstatus.h>

// 6. Include winternl.h AFTER windows.h
#include <winternl.h>

// 7. Our own structures for extended NT internals
#include "ntstructs.h"

// 8. Common macros
#ifndef NtCurrentProcess
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#endif

#endif // COMMON_DEFINES_H 