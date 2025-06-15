#include "../include/common_defines.h" // Should be the very first include

#include "../include/rdi.h"
#include "../include/utils.h"      // For FindExportedFunctionFromBuffer
#include "../include/rtldr_ctx.h"  // For PRTLDR_CTX
#include "../test_payload/include/reflective_loader.h" // Fixed path
#include "../include/syscalls.h" // For NTSTATUS codes
// #include <stdio.h> // Remove later

// Typedef for the ReflectiveLoader function pointer
typedef BOOL (WINAPI *pReflectiveLoader)(LPVOID);

// Standard RDI implementation approach
BOOL execute_reflective_dll(LPVOID dll_buffer, SIZE_T dll_size, LPVOID lpParameter) {
    if (!dll_buffer || dll_size == 0) {
        return FALSE;
    }

    // 1. Basic PE header validation
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)dll_buffer + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Check architecture (e.g., IMAGE_FILE_MACHINE_AMD64 for x64)
#ifdef _WIN64
    if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        return FALSE;
    }
#else
    if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        return FALSE;
    }
#endif

    // 2. Find the exported ReflectiveLoader function
    // The standard RDI approach relies on the DLL itself exporting this.
    // We need to parse the Export Table of the *in-memory buffer*.
    DWORD export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_dir_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (export_dir_rva == 0 || export_dir_size == 0) {
        return FALSE;
    }

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dll_buffer + export_dir_rva);
    
    DWORD* names_rva = (DWORD*)((BYTE*)dll_buffer + export_dir->AddressOfNames);
    DWORD* funcs_rva = (DWORD*)((BYTE*)dll_buffer + export_dir->AddressOfFunctions);
    WORD* ordinals_rva = (WORD*)((BYTE*)dll_buffer + export_dir->AddressOfNameOrdinals);

    pReflectiveLoader reflective_loader = NULL;
    DWORD loader_rva = 0;

    // Try finding by name "ReflectiveLoader" first (common convention)
    for (DWORD i = 0; i < export_dir->NumberOfNames; ++i) {
        char* name = (char*)((BYTE*)dll_buffer + names_rva[i]);
        if (_strcmp_no_crt(name, "ReflectiveLoader") == 0) { // Use our strcmp
            loader_rva = funcs_rva[ordinals_rva[i]];
            break;
        }
    }

    // If not found by name, try ordinal #1 (another convention)
    if (loader_rva == 0 && export_dir->NumberOfFunctions > 0) {
         // Check if ordinal 1 is valid within the AddressOfFunctions array bounds
         // Ordinals are Base-relative (export_dir->Base)
         if (export_dir->Base <= 1 && (1 - export_dir->Base) < export_dir->NumberOfFunctions) {
            loader_rva = funcs_rva[1 - export_dir->Base]; 
         }
    }

    if (loader_rva == 0) {
        return FALSE;
    }

    reflective_loader = (pReflectiveLoader)((BYTE*)dll_buffer + loader_rva);

    // 3. Call the ReflectiveLoader function
    // This function is responsible for:
    //    - Allocating memory for the mapped DLL
    //    - Copying PE headers and sections
    //    - Processing relocations
    //    - Resolving imports (using LoadLibrary/GetProcAddress or custom context)
    //    - Calling DllMain
    //    - Returning TRUE/FALSE
    BOOL result = reflective_loader(dll_buffer);

    return result;
}

// Placeholder for actual RDI logic if different from just calling an export.
// The current plan is to find and call "ReflectiveLoader" export.

NTSTATUS InvokeReflectiveLoader(
    PRTLDR_CTX ctx,
    PBYTE pPayloadBuffer, 
    LPCSTR reflectiveLoaderFunctionName, 
    LPVOID pParameter
) {
    if (!ctx || !ctx->syscalls_initialized || !pPayloadBuffer || !reflectiveLoaderFunctionName) {
        return STATUS_INVALID_PARAMETER; // Or a more specific error
    }

    // Find the exported ReflectiveLoader function from the in-memory DLL buffer
    pReflectiveLoader_t reflective_loader_ptr = (pReflectiveLoader_t)FindExportedFunctionFromBuffer(
                                                                        pPayloadBuffer, 
                                                                        reflectiveLoaderFunctionName
                                                                    );

    if (!reflective_loader_ptr) {
        // Optionally log: ReflectiveLoader function not found
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }

    // Call the ReflectiveLoader
    // The ReflectiveLoader is responsible for mapping the DLL into a new memory region,
    // handling relocations, resolving imports, and then calling its DllMain.
    // It should return the base address of the newly mapped module, or NULL on failure.
    LPVOID newModuleBase = reflective_loader_ptr(pParameter);

    if (!newModuleBase) {
        // Optionally log: ReflectiveLoader execution failed
        return STATUS_DLL_INIT_FAILED; // Or a more specific error indicating loader failure
    }

    // Optionally log: ReflectiveLoader executed successfully, new module base at newModuleBase
    return STATUS_SUCCESS;
}

// TODO: Review and remove execute_reflective_dll if InvokeReflectiveLoader covers its intended use.
/*
BOOL execute_reflective_dll(LPVOID dll_buffer, SIZE_T dll_size, LPVOID lpParameter) {
    if (!dll_buffer || dll_size == 0) {
        return FALSE;
    }

    // Assuming the buffer contains a PE file and exports ReflectiveLoader
    // This is a very simplified call, actual RDI involves more steps if not using a self-loader
    
    // Locate ReflectiveLoader export (simplified: assume it's the first export or known offset)
    // A more robust method would parse PE headers to find it by name or ordinal.
    // For this example, we might rely on the stub/test DLL having it at a known export.

    // This is where the test_payload/ReflectiveLoader.c steps in.
    // The function pointer should be to that ReflectiveLoader.
    pReflectiveLoader reflectiveLoader = (pReflectiveLoader)dll_buffer; // Placeholder, needs proper EAT parsing of the buffer!
    
    // (LPVOID)dll_buffer is passed as parameter to the reflective loader itself
    // return reflectiveLoader((LPVOID)dll_buffer); 
    return FALSE; // Placeholder, needs proper implementation
}
*/
