#ifndef PHANTOM_EDGE_UTILS_H
#define PHANTOM_EDGE_UTILS_H

#include <windows.h>    // Provides basic types like PVOID, HANDLE, DWORD, etc.
#include <winternl.h>   // Provides PEB, TEB, LDR structures

// Ensure PEB/LDR structures are defined correctly via included headers.
// If winternl.h doesn't pull them in automatically with windows.h for the target SDK,
// explicit inclusion might be needed here or in utils.c.

// Function to get the PEB address
PPEB GetPebAddress(void);

// Function to find the base address of a loaded module using PEB traversal
// pPeb: Pointer to the Process Environment Block
// module_name: Name of the module (case-insensitive comparison)
// Returns base address (PVOID) or NULL if not found
PVOID find_module_base_peb(PPEB pPeb, const wchar_t* module_name);

// Function to find the address of an exported function within a module
// module_base: Base address of the module to search
// function_name: Name of the function to find (case-sensitive)
// Returns function address (PVOID) or NULL if not found
PVOID find_function(PVOID module_base, const char* function_name);

// Helper for case-insensitive wide string comparison (No-CRT)
int _wcsicmp_no_crt(const wchar_t* s1, const wchar_t* s2);

// Helper for case-sensitive narrow string comparison (No-CRT)
// (Needed for find_function)
int _strcmp_no_crt(const char* s1, const char* s2);

#endif //PHANTOM_EDGE_UTILS_H 