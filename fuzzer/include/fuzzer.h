#ifndef FUZZER_H
#define FUZZER_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Fuzzing strategies
typedef enum {
    FUZZ_RANDOM_BYTES,      // Random byte mutations
    FUZZ_PE_AWARE,          // PE structure-aware mutations
    FUZZ_SECTION_CORRUPT,   // Corrupt specific PE sections
    FUZZ_IMPORT_CORRUPT,    // Corrupt import table
    FUZZ_EXPORT_CORRUPT,    // Corrupt export table
    FUZZ_HEADER_CORRUPT,    // Corrupt PE headers
    FUZZ_RELOC_CORRUPT,     // Corrupt relocation table
    FUZZ_RESOURCE_CORRUPT   // Corrupt resource section
} FUZZ_STRATEGY;

// Mutation operations
typedef enum {
    MUT_BIT_FLIP,           // Flip random bits
    MUT_BYTE_REPLACE,       // Replace bytes with random values
    MUT_BLOCK_REMOVE,       // Remove blocks of data
    MUT_BLOCK_DUPLICATE,    // Duplicate blocks
    MUT_BLOCK_SHUFFLE,      // Shuffle blocks
    MUT_INTEGER_OVERFLOW,   // Create integer overflows
    MUT_FORMAT_STRING,      // Insert format string patterns
    MUT_NULL_DEREF          // Create null pointer scenarios
} MUTATION_TYPE;

// Fuzzing context
typedef struct _FUZZ_CONTEXT {
    PBYTE original_pe;          // Original PE file
    SIZE_T original_size;       // Original file size
    PBYTE mutated_pe;          // Mutated PE buffer
    SIZE_T mutated_size;       // Mutated size
    FUZZ_STRATEGY strategy;     // Current strategy
    DWORD mutation_count;       // Number of mutations
    DWORD crash_count;          // Number of crashes found
    HANDLE log_file;            // Log file handle
} FUZZ_CONTEXT, *PFUZZ_CONTEXT;

// Test result
typedef struct _TEST_RESULT {
    BOOL crashed;               // Did it crash?
    DWORD exception_code;       // Exception code if crashed
    PVOID crash_address;        // Crash address
    CHAR description[256];      // Description of what happened
} TEST_RESULT, *PTEST_RESULT;

// PE Mutator functions
BOOL LoadPEFile(LPCSTR filename, PBYTE* buffer, PSIZE_T size);
BOOL MutatePE(PFUZZ_CONTEXT ctx, MUTATION_TYPE type);
BOOL SaveMutatedPE(PFUZZ_CONTEXT ctx, LPCSTR filename);

// Test harness functions
BOOL TestLoader(LPCSTR loader_path, PBYTE pe_buffer, SIZE_T pe_size, PTEST_RESULT result);
BOOL SetupCrashHandler(void);
VOID GenerateCrashDump(PEXCEPTION_POINTERS exception_info);
VOID SetCrashContext(PFUZZ_CONTEXT ctx, PTEST_RESULT result);

// Fuzzing engine
BOOL InitializeFuzzer(PFUZZ_CONTEXT ctx, LPCSTR pe_file);
VOID RunFuzzingCampaign(PFUZZ_CONTEXT ctx, LPCSTR loader_path, DWORD iterations);
VOID CleanupFuzzer(PFUZZ_CONTEXT ctx);

// Logging
VOID LogMessage(PFUZZ_CONTEXT ctx, LPCSTR format, ...);
VOID LogCrash(PFUZZ_CONTEXT ctx, PTEST_RESULT result);

#endif // FUZZER_H 