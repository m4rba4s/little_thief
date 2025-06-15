#include "include/fuzzer.h"

// Helper to get random value
static DWORD GetRandom(DWORD max) {
    return (DWORD)(((double)rand() / RAND_MAX) * max);
}

// Load PE file into memory
BOOL LoadPEFile(LPCSTR filename, PBYTE* buffer, PSIZE_T size) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    *size = (SIZE_T)fileSize.QuadPart;
    *buffer = (PBYTE)VirtualAlloc(NULL, *size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*buffer) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    DWORD bytesRead;
    BOOL result = ReadFile(hFile, *buffer, (DWORD)*size, &bytesRead, NULL);
    CloseHandle(hFile);
    
    if (!result || bytesRead != *size) {
        VirtualFree(*buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    return TRUE;
}

// Initialize fuzzer with PE file
BOOL InitializeFuzzer(PFUZZ_CONTEXT ctx, LPCSTR pe_file) {
    if (!LoadPEFile(pe_file, &ctx->original_pe, &ctx->original_size)) {
        return FALSE;
    }
    
    // Allocate buffer for mutations
    ctx->mutated_pe = (PBYTE)VirtualAlloc(NULL, ctx->original_size * 2, 
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ctx->mutated_pe) {
        VirtualFree(ctx->original_pe, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Create log file
    CHAR log_name[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(log_name, sizeof(log_name), "fuzz_log_%04d%02d%02d_%02d%02d%02d.txt",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    ctx->log_file = CreateFileA(log_name, GENERIC_WRITE, FILE_SHARE_READ,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    return TRUE;
}

// Mutate random bytes
static BOOL MutateRandomBytes(PFUZZ_CONTEXT ctx) {
    // Copy original to mutated buffer
    memcpy(ctx->mutated_pe, ctx->original_pe, ctx->original_size);
    ctx->mutated_size = ctx->original_size;
    
    // Number of bytes to mutate (1-10% of file)
    DWORD num_mutations = GetRandom((DWORD)(ctx->original_size * 0.1)) + 1;
    
    for (DWORD i = 0; i < num_mutations; i++) {
        DWORD offset = GetRandom((DWORD)ctx->original_size);
        ctx->mutated_pe[offset] = (BYTE)GetRandom(256);
    }
    
    return TRUE;
}

// Mutate PE headers
static BOOL MutatePEHeaders(PFUZZ_CONTEXT ctx) {
    memcpy(ctx->mutated_pe, ctx->original_pe, ctx->original_size);
    ctx->mutated_size = ctx->original_size;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ctx->mutated_pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(ctx->mutated_pe + dos->e_lfanew);
    
    // Randomly pick what to corrupt
    switch (GetRandom(6)) {
        case 0: // DOS header
            dos->e_magic = (WORD)GetRandom(0xFFFF);
            break;
        case 1: // PE signature
            nt->Signature = GetRandom(0xFFFFFFFF);
            break;
        case 2: // Machine type
            nt->FileHeader.Machine = (WORD)GetRandom(0xFFFF);
            break;
        case 3: // Number of sections
            nt->FileHeader.NumberOfSections = (WORD)GetRandom(100);
            break;
        case 4: // Size of image
            nt->OptionalHeader.SizeOfImage = GetRandom(0xFFFFFFFF);
            break;
        case 5: // Entry point
            nt->OptionalHeader.AddressOfEntryPoint = GetRandom(0xFFFFFFFF);
            break;
    }
    
    return TRUE;
}

// Corrupt PE section
static BOOL CorruptSection(PFUZZ_CONTEXT ctx) {
    memcpy(ctx->mutated_pe, ctx->original_pe, ctx->original_size);
    ctx->mutated_size = ctx->original_size;
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ctx->mutated_pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(ctx->mutated_pe + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    
    if (nt->FileHeader.NumberOfSections == 0) {
        return FALSE;
    }
    
    // Pick random section
    DWORD section_idx = GetRandom(nt->FileHeader.NumberOfSections);
    section += section_idx;
    
    // Corrupt section data
    switch (GetRandom(4)) {
        case 0: // Virtual size overflow
            section->Misc.VirtualSize = 0xFFFFFFFF;
            break;
        case 1: // Raw size overflow
            section->SizeOfRawData = 0xFFFFFFFF;
            break;
        case 2: // Invalid RVA
            section->VirtualAddress = GetRandom(0xFFFFFFFF);
            break;
        case 3: // Corrupt section data
            if (section->PointerToRawData < ctx->mutated_size &&
                section->SizeOfRawData > 0) {
                DWORD offset = section->PointerToRawData;
                DWORD size = min(section->SizeOfRawData, 
                                (DWORD)(ctx->mutated_size - offset));
                for (DWORD i = 0; i < size; i += GetRandom(100) + 1) {
                    ctx->mutated_pe[offset + i] = (BYTE)GetRandom(256);
                }
            }
            break;
    }
    
    return TRUE;
}

// Main mutation function
BOOL MutatePE(PFUZZ_CONTEXT ctx, MUTATION_TYPE type) {
    (void)type;
    BOOL result = FALSE;
    
    switch (ctx->strategy) {
        case FUZZ_RANDOM_BYTES:
            result = MutateRandomBytes(ctx);
            break;
        case FUZZ_PE_AWARE:
        case FUZZ_HEADER_CORRUPT:
            result = MutatePEHeaders(ctx);
            break;
        case FUZZ_SECTION_CORRUPT:
            result = CorruptSection(ctx);
            break;
        // TODO: Implement other strategies
        default:
            result = MutateRandomBytes(ctx);
            break;
    }
    
    if (result) {
        ctx->mutation_count++;
    }
    
    return result;
}

// Save mutated PE to file
BOOL SaveMutatedPE(PFUZZ_CONTEXT ctx, LPCSTR filename) {
    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, 
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    DWORD written;
    BOOL result = WriteFile(hFile, ctx->mutated_pe, (DWORD)ctx->mutated_size, 
                           &written, NULL);
    CloseHandle(hFile);
    
    return result && written == ctx->mutated_size;
}

// Cleanup fuzzer
VOID CleanupFuzzer(PFUZZ_CONTEXT ctx) {
    if (ctx->original_pe) {
        VirtualFree(ctx->original_pe, 0, MEM_RELEASE);
    }
    if (ctx->mutated_pe) {
        VirtualFree(ctx->mutated_pe, 0, MEM_RELEASE);
    }
    if (ctx->log_file != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->log_file);
    }
} 