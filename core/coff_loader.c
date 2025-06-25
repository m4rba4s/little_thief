#include "../include/common_defines.h"
#include "../include/coff_loader.h"
#include "../include/rtldr_ctx.h"
#include "../include/syscalls.h"
#include "../include/mem.h"
#include "../include/utils.h"

// ========================================================================
// ELITE BOF/COFF LOADING ENGINE v1.0 - IMPLEMENTATION
// "Loading any code, anywhere, anytime" - Elite BOF Master
// ========================================================================

// Global BOF loader configuration
static BOF_LOADER_CONFIG g_bof_config = {0};
static BOF_API_TABLE g_bof_api = {0};

// Common COFF section names
static const char* COFF_TEXT_SECTION = ".text";
static const char* COFF_DATA_SECTION = ".data";
static const char* COFF_RDATA_SECTION = ".rdata";
static const char* COFF_BSS_SECTION = ".bss";

// ========================================================================
// CORE INITIALIZATION
// ========================================================================

BOOL BOF_Initialize(struct _RTLDR_CTX* ctx, PBOF_LOADER_CONFIG config) {
    if (!ctx) {
        return FALSE;
    }

    // Set default configuration if none provided
    if (config) {
        g_bof_config = *config;
    } else {
        g_bof_config.enable_debug_output = FALSE;
        g_bof_config.strict_symbol_resolution = TRUE;
        g_bof_config.max_bof_size = 10 * 1024 * 1024; // 10MB max
        g_bof_config.symbol_timeout = 5000; // 5 seconds
    }

    // Initialize BOF API table
    if (!BOF_InitializeAPITable(&g_bof_api)) {
        return FALSE;
    }

    return TRUE;
}

// ========================================================================
// MAIN BOF LOADING FUNCTIONS
// ========================================================================

NTSTATUS BOF_LoadFromMemory(
    struct _RTLDR_CTX* ctx,
    PVOID coff_data,
    SIZE_T coff_size,
    PBOF_CONTEXT bof_ctx
) {
    if (!ctx || !coff_data || !coff_size || !bof_ctx) {
        return STATUS_INVALID_PARAMETER;
    }

    // Zero out BOF context
    for (SIZE_T i = 0; i < sizeof(BOF_CONTEXT); i++) {
        ((BYTE*)bof_ctx)[i] = 0;
    }

    // Validate COFF format
    if (!COFF_ValidateFormat(coff_data, coff_size)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Parse COFF header
    if (!COFF_ParseHeader(coff_data, coff_size, bof_ctx)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Calculate total memory needed
    SIZE_T total_size = 0;
    for (WORD i = 0; i < bof_ctx->file_header->NumberOfSections; i++) {
        PCOFF_SECTION_HEADER section = &bof_ctx->sections[i];
        if (section->SizeOfRawData > 0) {
            total_size += (section->SizeOfRawData + 0xFFF) & ~0xFFF; // Page align
        }
    }

    // Allocate memory for BOF
    NTSTATUS status = BOF_AllocateMemory(ctx, total_size, &bof_ctx->base_address);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    bof_ctx->total_size = total_size;

    // Parse and map sections
    status = COFF_ParseSections(coff_data, bof_ctx);
    if (!NT_SUCCESS(status)) {
        BOF_Cleanup(ctx, bof_ctx);
        return status;
    }

    // Parse symbols
    status = COFF_ParseSymbols(coff_data, bof_ctx);
    if (!NT_SUCCESS(status)) {
        BOF_Cleanup(ctx, bof_ctx);
        return status;
    }

    // Resolve external symbols
    status = BOF_ResolveExternalSymbols(ctx, bof_ctx);
    if (!NT_SUCCESS(status)) {
        BOF_Cleanup(ctx, bof_ctx);
        return status;
    }

    // Process relocations
    status = COFF_ProcessRelocations(coff_data, bof_ctx);
    if (!NT_SUCCESS(status)) {
        BOF_Cleanup(ctx, bof_ctx);
        return status;
    }

    // Set proper section protections
    status = BOF_SetSectionProtections(ctx, bof_ctx);
    if (!NT_SUCCESS(status)) {
        BOF_Cleanup(ctx, bof_ctx);
        return status;
    }

    // Find entry point (typically "go" function)
    bof_ctx->entry_point = BOF_GetInternalSymbol(bof_ctx, "go");
    if (!bof_ctx->entry_point) {
        // Try alternative entry point names
        bof_ctx->entry_point = BOF_GetInternalSymbol(bof_ctx, "_go");
        if (!bof_ctx->entry_point) {
            bof_ctx->entry_point = BOF_GetInternalSymbol(bof_ctx, "main");
        }
    }

    bof_ctx->is_loaded = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS BOF_LoadFromFile(
    struct _RTLDR_CTX* ctx,
    PCSTR file_path,
    PBOF_CONTEXT bof_ctx
) {
    // For now, return not implemented
    // Full file loading would use our syscall wrappers for NtCreateFile/NtReadFile
    return STATUS_NOT_IMPLEMENTED;
}

// ========================================================================
// BOF EXECUTION ENGINE
// ========================================================================

NTSTATUS BOF_Execute(
    struct _RTLDR_CTX* ctx,
    PBOF_CONTEXT bof_ctx,
    PCHAR arguments,
    DWORD argument_length
) {
    if (!ctx || !bof_ctx || !bof_ctx->is_loaded || !bof_ctx->entry_point) {
        return STATUS_INVALID_PARAMETER;
    }

    // Cast entry point to BOF function signature
    BOF_ENTRY_FUNCTION bof_entry = (BOF_ENTRY_FUNCTION)bof_ctx->entry_point;

    // Execute BOF (this is where the magic happens!)
    // Note: Using direct call without __try/__except for No-CRT compatibility
    // In production, could implement custom SEH handler
    bof_entry(arguments, argument_length);
    bof_ctx->is_executed = TRUE;

    return STATUS_SUCCESS;
}

// ========================================================================
// COFF PARSING IMPLEMENTATION
// ========================================================================

BOOL COFF_ValidateFormat(PVOID coff_data, SIZE_T coff_size) {
    if (!coff_data || coff_size < sizeof(COFF_FILE_HEADER)) {
        return FALSE;
    }

    PCOFF_FILE_HEADER header = (PCOFF_FILE_HEADER)coff_data;
    
    // Check machine type (x64)
#ifdef _WIN64
    if (header->Machine != 0x8664) { // IMAGE_FILE_MACHINE_AMD64
        return FALSE;
    }
#else
    if (header->Machine != 0x14c) { // IMAGE_FILE_MACHINE_I386
        return FALSE;
    }
#endif

    // Basic sanity checks
    if (header->NumberOfSections == 0 || header->NumberOfSections > 96) {
        return FALSE;
    }

    return TRUE;
}

BOOL COFF_ParseHeader(PVOID coff_data, SIZE_T coff_size, PBOF_CONTEXT bof_ctx) {
    bof_ctx->file_header = (PCOFF_FILE_HEADER)coff_data;
    
    // Sections start right after file header
    bof_ctx->sections = (PCOFF_SECTION_HEADER)((BYTE*)coff_data + sizeof(COFF_FILE_HEADER));
    
    return TRUE;
}

NTSTATUS COFF_ParseSections(PVOID coff_data, PBOF_CONTEXT bof_ctx) {
    BYTE* current_addr = (BYTE*)bof_ctx->base_address;
    
    // Copy each section to allocated memory
    for (WORD i = 0; i < bof_ctx->file_header->NumberOfSections; i++) {
        PCOFF_SECTION_HEADER section = &bof_ctx->sections[i];
        
        if (section->SizeOfRawData > 0) {
            // Update section virtual address to our allocated memory
            section->VirtualAddress = (DWORD)((ULONG_PTR)current_addr - (ULONG_PTR)bof_ctx->base_address);
            
            // Copy section data
            BYTE* section_data = (BYTE*)coff_data + section->PointerToRawData;
            for (DWORD j = 0; j < section->SizeOfRawData; j++) {
                current_addr[j] = section_data[j];
            }
            
            current_addr += (section->SizeOfRawData + 0xFFF) & ~0xFFF; // Page align
        }
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS COFF_ParseSymbols(PVOID coff_data, PBOF_CONTEXT bof_ctx) {
    if (bof_ctx->file_header->NumberOfSymbols == 0) {
        return STATUS_SUCCESS; // No symbols
    }
    
    // Symbol table starts at specified offset
    bof_ctx->symbols = (PCOFF_SYMBOL)((BYTE*)coff_data + bof_ctx->file_header->PointerToSymbolTable);
    
    // String table follows symbol table
    DWORD string_table_offset = bof_ctx->file_header->PointerToSymbolTable + 
                                (bof_ctx->file_header->NumberOfSymbols * sizeof(COFF_SYMBOL));
    bof_ctx->string_table = (PCHAR)((BYTE*)coff_data + string_table_offset);
    
    return STATUS_SUCCESS;
}

NTSTATUS COFF_ProcessRelocations(PVOID coff_data, PBOF_CONTEXT bof_ctx) {
    // Process relocations for each section
    for (WORD i = 0; i < bof_ctx->file_header->NumberOfSections; i++) {
        PCOFF_SECTION_HEADER section = &bof_ctx->sections[i];
        
        if (section->NumberOfRelocations == 0) {
            continue;
        }
        
        PCOFF_RELOCATION relocations = (PCOFF_RELOCATION)((BYTE*)coff_data + section->PointerToRelocations);
        
        for (WORD j = 0; j < section->NumberOfRelocations; j++) {
            PCOFF_RELOCATION reloc = &relocations[j];
            
            // Get symbol for this relocation
            if (reloc->SymbolTableIndex >= bof_ctx->file_header->NumberOfSymbols) {
                continue;
            }
            
            PCOFF_SYMBOL symbol = &bof_ctx->symbols[reloc->SymbolTableIndex];
            PVOID symbol_address = NULL;
            
            // Resolve symbol address
            if (symbol->SectionNumber > 0) {
                // Internal symbol
                PCOFF_SECTION_HEADER target_section = &bof_ctx->sections[symbol->SectionNumber - 1];
                symbol_address = (BYTE*)bof_ctx->base_address + target_section->VirtualAddress + symbol->Value;
            } else {
                // External symbol - would need to resolve from system libraries
                // For now, skip external symbols
                continue;
            }
            
            // Apply relocation (simplified for x64)
            PVOID reloc_address = (BYTE*)bof_ctx->base_address + section->VirtualAddress + reloc->VirtualAddress;
            
#ifdef _WIN64
            if (reloc->Type == 1) { // IMAGE_REL_AMD64_ADDR64
                *(PULONG64)reloc_address = (ULONG64)symbol_address;
            } else if (reloc->Type == 4) { // IMAGE_REL_AMD64_REL32
                LONG64 relative = (LONG64)symbol_address - ((LONG64)reloc_address + 4);
                *(PLONG)reloc_address = (LONG)relative;
            }
#endif
        }
    }
    
    return STATUS_SUCCESS;
}

// ========================================================================
// SYMBOL RESOLUTION ENGINE
// ========================================================================

NTSTATUS BOF_ResolveExternalSymbols(struct _RTLDR_CTX* ctx, PBOF_CONTEXT bof_ctx) {
    // For now, basic implementation
    // Full implementation would resolve ntdll, kernel32 functions etc.
    return STATUS_SUCCESS;
}

PVOID BOF_ResolveSymbol(struct _RTLDR_CTX* ctx, PCSTR symbol_name) {
    // Try resolving from ntdll first
    if (ctx->ntdll_base) {
        PVOID addr = find_function(ctx->ntdll_base, symbol_name);
        if (addr) {
            return addr;
        }
    }
    
    // Could add kernel32, other system DLLs here
    return NULL;
}

PVOID BOF_GetInternalSymbol(PBOF_CONTEXT bof_ctx, PCSTR symbol_name) {
    if (!bof_ctx->symbols || !symbol_name) {
        return NULL;
    }
    
    // Search symbol table
    for (DWORD i = 0; i < bof_ctx->file_header->NumberOfSymbols; i++) {
        PCOFF_SYMBOL symbol = &bof_ctx->symbols[i];
        PCSTR current_name = COFF_GetSymbolName(bof_ctx, symbol);
        
        if (current_name) {
            // Simple string comparison (should use proper string compare)
            BOOL match = TRUE;
            for (int j = 0; symbol_name[j] || current_name[j]; j++) {
                if (symbol_name[j] != current_name[j]) {
                    match = FALSE;
                    break;
                }
            }
            
            if (match && symbol->SectionNumber > 0) {
                PCOFF_SECTION_HEADER section = &bof_ctx->sections[symbol->SectionNumber - 1];
                return (BYTE*)bof_ctx->base_address + section->VirtualAddress + symbol->Value;
            }
        }
    }
    
    return NULL;
}

// ========================================================================
// MEMORY MANAGEMENT
// ========================================================================

NTSTATUS BOF_AllocateMemory(struct _RTLDR_CTX* ctx, SIZE_T size, PVOID* base_address) {
    return alloc_memory(base_address, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

NTSTATUS BOF_SetSectionProtections(struct _RTLDR_CTX* ctx, PBOF_CONTEXT bof_ctx) {
    // Set appropriate protections for each section
    for (WORD i = 0; i < bof_ctx->file_header->NumberOfSections; i++) {
        PCOFF_SECTION_HEADER section = &bof_ctx->sections[i];
        
        if (section->SizeOfRawData == 0) continue;
        
        PVOID section_addr = (BYTE*)bof_ctx->base_address + section->VirtualAddress;
        SIZE_T section_size = section->SizeOfRawData;
        DWORD protection = PAGE_READONLY;
        
        // Determine protection based on section characteristics
        if (section->Characteristics & 0x20000000) { // IMAGE_SCN_MEM_EXECUTE
            if (section->Characteristics & 0x80000000) { // IMAGE_SCN_MEM_WRITE
                protection = PAGE_EXECUTE_READWRITE;
            } else {
                protection = PAGE_EXECUTE_READ;
            }
        } else if (section->Characteristics & 0x80000000) { // IMAGE_SCN_MEM_WRITE
            protection = PAGE_READWRITE;
        }
        
        ULONG old_protection;
        protect_memory(section_addr, section_size, protection, &old_protection);
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS BOF_FreeMemory(struct _RTLDR_CTX* ctx, PVOID base_address, SIZE_T size) {
    return free_memory(base_address, 0, MEM_RELEASE);
}

// ========================================================================
// UTILITY FUNCTIONS
// ========================================================================

PCSTR COFF_GetSymbolName(PBOF_CONTEXT bof_ctx, PCOFF_SYMBOL symbol) {
    if (symbol->N.LongName.Zeros == 0) {
        // Long name stored in string table
        return bof_ctx->string_table + symbol->N.LongName.Offset;
    } else {
        // Short name stored directly (max 8 chars)
        return (PCSTR)symbol->N.Name;
    }
}

VOID BOF_Cleanup(struct _RTLDR_CTX* ctx, PBOF_CONTEXT bof_ctx) {
    if (bof_ctx->base_address) {
        BOF_FreeMemory(ctx, bof_ctx->base_address, bof_ctx->total_size);
    }
    
    // Zero out context
    for (SIZE_T i = 0; i < sizeof(BOF_CONTEXT); i++) {
        ((BYTE*)bof_ctx)[i] = 0;
    }
}

// ========================================================================
// BOF API TABLE IMPLEMENTATION
// ========================================================================

BOOL BOF_InitializeAPITable(PBOF_API_TABLE api_table) {
    if (!api_table) return FALSE;
    
    // Initialize BOF API functions (simplified for now)
    for (SIZE_T i = 0; i < sizeof(BOF_API_TABLE); i++) {
        ((BYTE*)api_table)[i] = 0;
    }
    
    // TODO: Implement actual BOF API functions
    return TRUE;
} 