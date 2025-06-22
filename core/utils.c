#include "../include/common_defines.h"
#include <intrin.h>   // For __readgsqword / __readfsdword
#include "../include/utils.h"
#include "../include/ntstructs.h"  // For extended LDR structures

// Helper for case-insensitive wide string comparison (No-CRT)
int _wcsicmp_no_crt(const wchar_t* s1, const wchar_t* s2) {
    wchar_t c1, c2;
    if (s1 == s2) return 0; // Handles null == null
    if (!s1) return -1;     // null < non-null
    if (!s2) return 1;      // non-null > null

    do {
        c1 = *s1++;
        c2 = *s2++;
        // Convert to lowercase
        if (c1 >= L'A' && c1 <= L'Z') c1 += L'a' - L'A';
        if (c2 >= L'A' && c2 <= L'Z') c2 += L'a' - L'A';
    } while (c1 && (c1 == c2));

    // The cast to unsigned prevents issues with sign extension
    return (int)(unsigned short)c1 - (int)(unsigned short)c2;
}

// Helper for case-sensitive narrow string comparison (No-CRT)
int _strcmp_no_crt(const char* s1, const char* s2) {
    if (s1 == s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;

    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}


// Function to get the PEB address using intrinsics
PPEB GetPebAddress(void) {
#ifdef _WIN64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

// Function to find the base address of a loaded module using PEB traversal
// pPeb: Pointer to the Process Environment Block (obtain using GetPebAddress)
// module_name: Name of the module (case-insensitive comparison)
// Returns base address (PVOID) or NULL if not found
PVOID find_module_base_peb(PPEB pPeb, const wchar_t* module_name) {
    if (!pPeb || !module_name) {
        return NULL;
    }

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    if (!pLdr) {
        return NULL;
    }

    PLIST_ENTRY listHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY currentEntry = listHead->Flink;

    while (currentEntry != listHead) {
        // Get pointer to LDR_DATA_TABLE_ENTRY from the LIST_ENTRY member
        PLDR_DATA_TABLE_ENTRY_EX pEntry = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY_EX, InMemoryOrderLinks);

        // Check if BaseDllName is valid and compare (case-insensitive)
        // Use BaseDllName for comparison as it's generally shorter and sufficient
        if (pEntry->BaseDllName.Buffer && pEntry->BaseDllName.Length > 0) {
            // Perform case-insensitive comparison
            if (_wcsicmp_no_crt(pEntry->BaseDllName.Buffer, module_name) == 0) {
                return (HMODULE)pEntry->DllBase;
            }
        }
        /* // Alternative: Check FullDllName if BaseDllName fails or isn't reliable
        else if (pEntry->FullDllName.Buffer && pEntry->FullDllName.Length > 0) {
             // Need a function to extract base name from full path here if using FullDllName
             const wchar_t* baseName = GetBaseDllNameFromPath(pEntry->FullDllName.Buffer); // Assuming such helper exists
             if (baseName && _wcsicmp_no_crt(module_name, baseName) == 0) {
                 return pEntry->DllBase;
             }
        }
        */

        currentEntry = currentEntry->Flink; // Move to next entry
    }

    return NULL; // Module not found
}

// Implementation for the public find_module_base function
PVOID find_module_base(LPCWSTR module_name) {
    PPEB peb = GetPebAddress();
    if (!peb) return NULL;
    return find_module_base_peb(peb, module_name);
}

// Custom implementation of string comparison (case-insensitive)
// Find the address of an exported function within a module's EAT.
// Does not rely on GetProcAddress.
PVOID find_function(PVOID module_base, const char* function_name) {
    if (!module_base || !function_name) {
        return NULL;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        // Invalid DOS signature
        return NULL;
    }

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        // Invalid NT signature
        return NULL;
    }

    // Check if export directory exists and has size
    if (nt_headers->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return NULL; // No export directory entry
    }
    IMAGE_DATA_DIRECTORY* export_dir_entry = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir_entry->VirtualAddress == 0 || export_dir_entry->Size == 0) {
        return NULL; // Export directory is empty or doesn't exist
    }

    // Get pointer to the Export Directory structure
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module_base + export_dir_entry->VirtualAddress);

    // Get pointers to the relevant arrays using RVAs from the Export Directory
    DWORD* address_of_functions = (DWORD*)((BYTE*)module_base + export_dir->AddressOfFunctions);
    DWORD* address_of_names = (DWORD*)((BYTE*)module_base + export_dir->AddressOfNames);
    WORD* address_of_name_ordinals = (WORD*)((BYTE*)module_base + export_dir->AddressOfNameOrdinals);

    // Iterate through the names array
    for (DWORD i = 0; i < export_dir->NumberOfNames; ++i) {
        // Get the name string using RVA from address_of_names
        char* current_function_name = (char*)((BYTE*)module_base + address_of_names[i]);

        // Compare the current function name with the target function name (case-sensitive)
        if (_strcmp_no_crt(function_name, current_function_name) == 0) {
            // Name matches, find the corresponding ordinal
            WORD ordinal = address_of_name_ordinals[i];

            // Check if the ordinal is within the valid range of functions
            if (ordinal < export_dir->NumberOfFunctions) {
                // Get the function's RVA from address_of_functions using the ordinal
                DWORD function_rva = address_of_functions[ordinal];

                // Check for forwarded exports (where RVA points inside the export directory itself)
                // For simplicity, we don't handle forwarded exports here and return NULL.
                // A more complete implementation might recursively resolve them.
                 if (function_rva >= export_dir_entry->VirtualAddress &&
                     function_rva < export_dir_entry->VirtualAddress + export_dir_entry->Size) {
                     // Forwarded export, not handled
                     return NULL;
                 }

                // Calculate the actual function address (VA)
                return (PVOID)((BYTE*)module_base + function_rva);
            }
        }
    }

    // Function name not found in the export table
    return NULL;
}

// New Function: FindExportedFunctionFromBuffer
// Finds an exported function from a DLL image already in memory (a buffer).
FARPROC FindExportedFunctionFromBuffer(PBYTE pImageBase, LPCSTR functionName) {
    if (!pImageBase || !functionName) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        // Invalid DOS signature
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        // Invalid NT signature
        return NULL;
    }

    // Ensure it's a DLL (though loader might load EXEs reflectively too in advanced scenarios)
    // if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
    //     return NULL; // Not a DLL
    // }

    PIMAGE_DATA_DIRECTORY pExportDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (pExportDataDir->VirtualAddress == 0 || pExportDataDir->Size == 0) {
        // No export table
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pImageBase + pExportDataDir->VirtualAddress);

    PDWORD pNames = (PDWORD)(pImageBase + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)(pImageBase + pExportDir->AddressOfNameOrdinals);
    PDWORD pFunctions = (PDWORD)(pImageBase + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
        LPCSTR currentExportName = (LPCSTR)(pImageBase + pNames[i]);

        // Simple string comparison (case-sensitive, like GetProcAddress)
        LPCSTR target = functionName;
        LPCSTR current = currentExportName;
        while (*current != 0 && *target != 0 && *current == *target) {
            current++;
            target++;
        }

        if (*current == 0 && *target == 0) { // Names match
            WORD ordinal = pOrdinals[i];
            if (ordinal < pExportDir->NumberOfFunctions) { // Check bounds for AddressOfFunctions
                 // Check if it's a forwarded export
                DWORD funcRVA = pFunctions[ordinal];
                if (funcRVA >= pExportDataDir->VirtualAddress && 
                    funcRVA < pExportDataDir->VirtualAddress + pExportDataDir->Size) {
                    // This is a forwarded export (e.g., "MYDLL.ActualFunction")
                    // Handling forwarded exports is more complex and typically not needed for ReflectiveLoader itself.
                    // For now, we assume direct exports for simplicity in this loader.
                    // If needed, one would parse the forwarder string and call find_function/GetProcAddress on the target DLL.
                    return NULL; // Forwarded exports not handled here
                }
                return (FARPROC)(pImageBase + funcRVA);
            }
        }
    }

    return NULL; // Function not found
} 