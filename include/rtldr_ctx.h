#ifndef RTLDR_CTX_H
#define RTLDR_CTX_H

#include "common_defines.h"
#include "syscalls.h"   // Include syscalls FIRST to get SYSCALL_TABLE definition

// Forward declare the strategy structure to avoid including strategy.h
struct _EVASION_STRATEGY;

// Main context structure for the runtime loader
typedef struct _RTLDR_CTX {
    // Module bases
    HMODULE ntdll_base;
    // HMODULE kernel32_base; // etc.

    // Syscall table, defined in syscalls.h
    SYSCALL_TABLE syscalls;
    BOOL syscalls_initialized;

    // Evasion strategy module
    struct _EVASION_STRATEGY* strategy;

} RTLDR_CTX, *PRTLDR_CTX;

#endif // RTLDR_CTX_H 