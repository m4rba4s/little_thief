#ifndef COFF_LOADER_H
#define COFF_LOADER_H

#include "common_defines.h"

// Forward declarations
struct _RTLDR_CTX;

// ========================================================================
// ELITE BOF/COFF LOADING ENGINE v1.0
// Techniques: COFF parsing, Symbol resolution, Dynamic linking, BOF execution
// Features: No-CRT, Syscall integration, Memory management, Error handling
// ========================================================================

// COFF file header structure
typedef struct _COFF_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} COFF_FILE_HEADER, *PCOFF_FILE_HEADER;

// COFF section header
typedef struct _COFF_SECTION_HEADER {
    BYTE Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION_HEADER, *PCOFF_SECTION_HEADER;

// COFF symbol table entry
typedef struct _COFF_SYMBOL {
    union {
        BYTE Name[8];
        struct {
            DWORD Zeros;
            DWORD Offset;
        } LongName;
    } N;
    DWORD Value;
    SHORT SectionNumber;
    WORD Type;
    BYTE StorageClass;
    BYTE NumberOfAuxSymbols;
} COFF_SYMBOL, *PCOFF_SYMBOL;

// COFF relocation entry
typedef struct _COFF_RELOCATION {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD Type;
} COFF_RELOCATION, *PCOFF_RELOCATION;

// BOF execution context
typedef struct _BOF_CONTEXT {
    PVOID base_address;              // Allocated memory for BOF
    SIZE_T total_size;               // Total allocated size
    PCOFF_FILE_HEADER file_header;   // COFF file header
    PCOFF_SECTION_HEADER sections;   // Section headers array
    PCOFF_SYMBOL symbols;            // Symbol table
    PCHAR string_table;              // String table for long names
    PVOID entry_point;               // BOF entry function
    BOOL is_loaded;                  // Load status
    BOOL is_executed;                // Execution status
} BOF_CONTEXT, *PBOF_CONTEXT;

// BOF function signature (standard BOF entry point)
typedef VOID (*BOF_ENTRY_FUNCTION)(PCHAR arguments, DWORD argument_length);

// Symbol resolution information
typedef struct _BOF_SYMBOL_RESOLUTION {
    PCHAR symbol_name;
    PVOID symbol_address;
    BOOL is_resolved;
} BOF_SYMBOL_RESOLUTION, *PBOF_SYMBOL_RESOLUTION;

// BOF loader configuration
typedef struct _BOF_LOADER_CONFIG {
    BOOL enable_debug_output;
    BOOL strict_symbol_resolution;
    DWORD max_bof_size;              // Maximum BOF size in bytes
    DWORD symbol_timeout;            // Symbol resolution timeout
} BOF_LOADER_CONFIG, *PBOF_LOADER_CONFIG;

// ========================================================================
// CORE BOF/COFF LOADING FUNCTIONS
// ========================================================================

// Initialize BOF loader with configuration
BOOL BOF_Initialize(struct _RTLDR_CTX* ctx, PBOF_LOADER_CONFIG config);

// Load BOF from memory buffer
NTSTATUS BOF_LoadFromMemory(
    struct _RTLDR_CTX* ctx,
    PVOID coff_data,
    SIZE_T coff_size,
    PBOF_CONTEXT bof_ctx
);

// Load BOF from file path
NTSTATUS BOF_LoadFromFile(
    struct _RTLDR_CTX* ctx,
    PCSTR file_path,
    PBOF_CONTEXT bof_ctx
);

// Execute loaded BOF with arguments
NTSTATUS BOF_Execute(
    struct _RTLDR_CTX* ctx,
    PBOF_CONTEXT bof_ctx,
    PCHAR arguments,
    DWORD argument_length
);

// Cleanup BOF resources
VOID BOF_Cleanup(struct _RTLDR_CTX* ctx, PBOF_CONTEXT bof_ctx);

// ========================================================================
// COFF PARSING FUNCTIONS
// ========================================================================

// Parse COFF file header and validate
BOOL COFF_ParseHeader(PVOID coff_data, SIZE_T coff_size, PBOF_CONTEXT bof_ctx);

// Parse and map COFF sections
NTSTATUS COFF_ParseSections(PVOID coff_data, PBOF_CONTEXT bof_ctx);

// Parse symbol table and string table
NTSTATUS COFF_ParseSymbols(PVOID coff_data, PBOF_CONTEXT bof_ctx);

// Process relocations for loaded sections
NTSTATUS COFF_ProcessRelocations(PVOID coff_data, PBOF_CONTEXT bof_ctx);

// ========================================================================
// SYMBOL RESOLUTION ENGINE
// ========================================================================

// Resolve external symbols (ntdll, kernel32, etc.)
NTSTATUS BOF_ResolveExternalSymbols(struct _RTLDR_CTX* ctx, PBOF_CONTEXT bof_ctx);

// Resolve single symbol by name
PVOID BOF_ResolveSymbol(struct _RTLDR_CTX* ctx, PCSTR symbol_name);

// Get BOF internal symbol address
PVOID BOF_GetInternalSymbol(PBOF_CONTEXT bof_ctx, PCSTR symbol_name);

// ========================================================================
// MEMORY MANAGEMENT
// ========================================================================

// Allocate memory for BOF with proper permissions
NTSTATUS BOF_AllocateMemory(struct _RTLDR_CTX* ctx, SIZE_T size, PVOID* base_address);

// Set section memory protections
NTSTATUS BOF_SetSectionProtections(struct _RTLDR_CTX* ctx, PBOF_CONTEXT bof_ctx);

// Free BOF allocated memory
NTSTATUS BOF_FreeMemory(struct _RTLDR_CTX* ctx, PVOID base_address, SIZE_T size);

// ========================================================================
// UTILITY FUNCTIONS
// ========================================================================

// Validate COFF file format
BOOL COFF_ValidateFormat(PVOID coff_data, SIZE_T coff_size);

// Get section by name
PCOFF_SECTION_HEADER COFF_GetSectionByName(PBOF_CONTEXT bof_ctx, PCSTR section_name);

// Get symbol name (handles long names in string table)
PCSTR COFF_GetSymbolName(PBOF_CONTEXT bof_ctx, PCOFF_SYMBOL symbol);

// Check if section is executable
BOOL COFF_IsSectionExecutable(PCOFF_SECTION_HEADER section);

// ========================================================================
// PREDEFINED SYMBOL EXPORTS (BOF API)
// ========================================================================

// Standard BOF API functions that we provide to loaded BOFs
typedef struct _BOF_API_TABLE {
    // Memory functions
    PVOID (*BeaconDataParse)(PVOID data, DWORD size);
    VOID (*BeaconDataFree)(PVOID data);
    
    // Output functions  
    VOID (*BeaconPrintf)(DWORD type, PCSTR format, ...);
    VOID (*BeaconOutput)(DWORD type, PCHAR data, DWORD length);
    
    // WinAPI wrappers (using our syscalls)
    HANDLE (*BeaconGetCurrentProcess)(VOID);
    DWORD (*BeaconGetCurrentProcessId)(VOID);
    
    // Custom PhantomEdge extensions
    NTSTATUS (*PhantomAlloc)(PVOID* address, SIZE_T size);
    NTSTATUS (*PhantomFree)(PVOID address, SIZE_T size);
    NTSTATUS (*PhantomProtect)(PVOID address, SIZE_T size, DWORD protection);
    
} BOF_API_TABLE, *PBOF_API_TABLE;

// Initialize BOF API table
BOOL BOF_InitializeAPITable(PBOF_API_TABLE api_table);

#endif // COFF_LOADER_H 