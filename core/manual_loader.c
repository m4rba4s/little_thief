#include "../include/common_defines.h"
#include "../include/manual_loader.h"
#include "../include/rtldr_ctx.h"
#include "../include/syscalls.h"
#include "../include/mem.h"
#include "../include/utils.h"

// Advanced PE parsing with stealth techniques
NTSTATUS ParsePEHeaders(PVOID image_base, PMANUAL_LOAD_CONTEXT load_ctx) {
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_NT_HEADERS nt_headers = NULL;
    PIMAGE_SECTION_HEADER sections = NULL;
    
    if (!image_base || !load_ctx) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Zero out context
    for (SIZE_T i = 0; i < sizeof(MANUAL_LOAD_CONTEXT); i++) {
        ((BYTE*)load_ctx)[i] = 0;
    }
    
    // Validate DOS header
    dos_header = (PIMAGE_DOS_HEADER)image_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    
    // Get NT headers
    nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)image_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    
    // Validate architecture
#ifdef _WIN64
    if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
#else
    if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
#endif
    
    // Get sections
    sections = IMAGE_FIRST_SECTION(nt_headers);
    
    // Fill context
    load_ctx->BaseAddress = image_base;
    load_ctx->ImageSize = nt_headers->OptionalHeader.SizeOfImage;
    load_ctx->EntryPoint = (BYTE*)image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;
    load_ctx->NtHeaders = nt_headers;
    load_ctx->Sections = sections;
    load_ctx->NumberOfSections = nt_headers->FileHeader.NumberOfSections;
    load_ctx->IsLoaded = FALSE;
    
    return STATUS_SUCCESS;
}

// Allocate unbacked (private) memory to bypass load callbacks
NTSTATUS AllocateUnbackedMemory(PRTLDR_CTX ctx, PVOID* memory_address, SIZE_T* memory_size, ULONG protection) {
    NTSTATUS status;
    PVOID base_address = NULL;
    SIZE_T region_size = *memory_size;
    
    if (!ctx || !memory_address || !memory_size) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Allocate private memory (unbacked) to bypass image load callbacks
    status = wrapped_NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &base_address,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        protection
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    *memory_address = base_address;
    *memory_size = region_size;
    
    return STATUS_SUCCESS;
}

// Process relocations for manual loading
NTSTATUS ProcessRelocations(PRTLDR_CTX ctx, PMANUAL_LOAD_CONTEXT load_ctx, PVOID new_base) {
    PIMAGE_BASE_RELOCATION reloc_dir = NULL;
    PIMAGE_DATA_DIRECTORY reloc_data_dir = NULL;
    ULONG_PTR delta = 0;
    
    if (!ctx || !load_ctx || !new_base) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Get relocation directory
    reloc_data_dir = &load_ctx->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_data_dir->Size == 0) {
        return STATUS_SUCCESS; // No relocations needed
    }
    
    reloc_dir = (PIMAGE_BASE_RELOCATION)((BYTE*)load_ctx->BaseAddress + reloc_data_dir->VirtualAddress);
    delta = (ULONG_PTR)new_base - load_ctx->NtHeaders->OptionalHeader.ImageBase;
    
    if (delta == 0) {
        return STATUS_SUCCESS; // Already at preferred base
    }
    
    // Process each relocation block
    while (reloc_dir->SizeOfBlock > 0) {
        ULONG entries_count = (reloc_dir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD reloc_entries = (PWORD)((BYTE*)reloc_dir + sizeof(IMAGE_BASE_RELOCATION));
        
        for (ULONG i = 0; i < entries_count; i++) {
            WORD reloc_entry = reloc_entries[i];
            WORD type = (reloc_entry >> 12) & 0xF;
            WORD offset = reloc_entry & 0xFFF;
            PVOID reloc_address = (BYTE*)new_base + reloc_dir->VirtualAddress + offset;
            
            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // Skip
                    break;
                    
                case IMAGE_REL_BASED_HIGHLOW:
                    *(PULONG)reloc_address += (ULONG)delta;
                    break;
                    
                case IMAGE_REL_BASED_DIR64:
                    *(PULONG_PTR)reloc_address += delta;
                    break;
                    
                default:
                    // Unknown relocation type
                    break;
            }
        }
        
        // Move to next relocation block
        reloc_dir = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc_dir + reloc_dir->SizeOfBlock);
    }
    
    return STATUS_SUCCESS;
}

// Main manual loading function with advanced evasion
NTSTATUS ManualLoadLibrary(PRTLDR_CTX ctx, PVOID buffer_or_path, PVOID* loaded_module, ULONG flags) {
    NTSTATUS status;
    MANUAL_LOAD_CONTEXT load_ctx = {0};
    PVOID target_base = NULL;
    SIZE_T target_size = 0;
    PVOID source_image = buffer_or_path;
    
    if (!ctx || !buffer_or_path || !loaded_module) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Parse PE headers
    status = ParsePEHeaders(source_image, &load_ctx);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    load_ctx.Flags = flags;
    target_size = load_ctx.ImageSize;
    
    // Allocate memory for the image
    if (flags & MANUAL_LOAD_UNBACKED_MEMORY) {
        status = AllocateUnbackedMemory(ctx, &target_base, &target_size, PAGE_READWRITE);
    } else {
        status = wrapped_NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &target_base,
            0,
            &target_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
    }
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Copy headers
    for (SIZE_T i = 0; i < load_ctx.NtHeaders->OptionalHeader.SizeOfHeaders; i++) {
        ((BYTE*)target_base)[i] = ((BYTE*)source_image)[i];
    }
    
    // Copy sections
    for (WORD i = 0; i < load_ctx.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = &load_ctx.Sections[i];
        PVOID dest = (BYTE*)target_base + section->VirtualAddress;
        PVOID src = (BYTE*)source_image + section->PointerToRawData;
        SIZE_T size = section->SizeOfRawData;
        
        if (size > section->Misc.VirtualSize) {
            size = section->Misc.VirtualSize;
        }
        
        for (SIZE_T j = 0; j < size; j++) {
            ((BYTE*)dest)[j] = ((BYTE*)src)[j];
        }
    }
    
    // Update context with new base
    load_ctx.BaseAddress = target_base;
    
    // Process relocations
    status = ProcessRelocations(ctx, &load_ctx, target_base);
    if (!NT_SUCCESS(status)) {
        wrapped_NtFreeVirtualMemory(NtCurrentProcess(), &target_base, &target_size, MEM_RELEASE);
        return status;
    }
    
    *loaded_module = target_base;
    return STATUS_SUCCESS;
}

// Get procedure address from manually loaded module
PVOID ManualGetProcAddress(PRTLDR_CTX ctx, PVOID module_base, PCHAR function_name) {
    PIMAGE_DOS_HEADER dos_header = NULL;
    PIMAGE_NT_HEADERS nt_headers = NULL;
    PIMAGE_EXPORT_DIRECTORY export_dir = NULL;
    PIMAGE_DATA_DIRECTORY export_data_dir = NULL;
    PULONG name_rvas = NULL;
    PUSHORT ordinals = NULL;
    PULONG func_rvas = NULL;
    
    if (!ctx || !module_base || !function_name) {
        return NULL;
    }
    
    dos_header = (PIMAGE_DOS_HEADER)module_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    
    nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    
    export_data_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_data_dir->Size == 0) {
        return NULL;
    }
    
    export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module_base + export_data_dir->VirtualAddress);
    name_rvas = (PULONG)((BYTE*)module_base + export_dir->AddressOfNames);
    ordinals = (PUSHORT)((BYTE*)module_base + export_dir->AddressOfNameOrdinals);
    func_rvas = (PULONG)((BYTE*)module_base + export_dir->AddressOfFunctions);
    
    // Search for function by name
    for (ULONG i = 0; i < export_dir->NumberOfNames; i++) {
        PCHAR export_name = (PCHAR)((BYTE*)module_base + name_rvas[i]);
        
        // Simple string comparison
        BOOL match = TRUE;
        for (SIZE_T j = 0; export_name[j] || function_name[j]; j++) {
            if (export_name[j] != function_name[j]) {
                match = FALSE;
                break;
            }
        }
        
        if (match) {
            ULONG func_rva = func_rvas[ordinals[i]];
            return (BYTE*)module_base + func_rva;
        }
    }
    
    return NULL;
}

// Unload manually loaded library
NTSTATUS ManualUnloadLibrary(PRTLDR_CTX ctx, PVOID loaded_module) {
    SIZE_T region_size = 0;
    
    if (!ctx || !loaded_module) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Free the allocated memory
    return wrapped_NtFreeVirtualMemory(
        NtCurrentProcess(),
        &loaded_module,
        &region_size,
        MEM_RELEASE
    );
} 