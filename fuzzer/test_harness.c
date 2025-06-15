#include "include/fuzzer.h"

#define MUT_RANDOM_BYTES 0

// Test loader with mutated PE
BOOL TestLoader(LPCSTR loader_path, PBYTE pe_buffer, SIZE_T pe_size, PTEST_RESULT result) {
    // Initialize result
    ZeroMemory(result, sizeof(TEST_RESULT));
    
    // Create temporary file for mutated PE
    CHAR temp_path[MAX_PATH];
    CHAR temp_file[MAX_PATH];
    GetTempPathA(sizeof(temp_path), temp_path);
    GetTempFileNameA(temp_path, "fuzz", 0, temp_file);
    
    // Write mutated PE to temp file
    HANDLE hFile = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    DWORD written;
    WriteFile(hFile, pe_buffer, (DWORD)pe_size, &written, NULL);
    CloseHandle(hFile);
    
    // Prepare process creation
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    // Create command line
    CHAR cmdline[MAX_PATH * 2];
    sprintf_s(cmdline, sizeof(cmdline), "\"%s\" \"%s\"", loader_path, temp_file);
    
    // Create loader process
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_SUSPENDED | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                       NULL, NULL, &si, &pi)) {
        DeleteFileA(temp_file);
        return FALSE;
    }
    
    // Resume process
    ResumeThread(pi.hThread);
    
    // Debug loop with timeout
    DWORD start_time = GetTickCount();
    DWORD timeout_ms = 5000; // 5 second timeout
    BOOL process_crashed = FALSE;
    
    while (TRUE) {
        DEBUG_EVENT debug_event;
        
        // Check timeout
        if (GetTickCount() - start_time > timeout_ms) {
            // Timeout - terminate process
            TerminateProcess(pi.hProcess, 0xDEADBEEF);
            strcpy_s(result->description, sizeof(result->description), "Process timeout");
            break;
        }
        
        // Wait for debug event
        if (!WaitForDebugEvent(&debug_event, 100)) {
            continue;
        }
        
        DWORD continue_status = DBG_CONTINUE;
        
        switch (debug_event.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT:
                // First chance exception
                if (debug_event.u.Exception.dwFirstChance) {
                    // Check if it's a real crash
                    DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
                    if (code == EXCEPTION_ACCESS_VIOLATION ||
                        code == EXCEPTION_STACK_OVERFLOW ||
                        code == EXCEPTION_ILLEGAL_INSTRUCTION ||
                        code == EXCEPTION_PRIV_INSTRUCTION ||
                        code == EXCEPTION_INT_DIVIDE_BY_ZERO ||
                        code == EXCEPTION_FLT_DIVIDE_BY_ZERO ||
                        code == EXCEPTION_ARRAY_BOUNDS_EXCEEDED ||
                        code == EXCEPTION_DATATYPE_MISALIGNMENT) {
                        
                        // Real crash detected
                        result->crashed = TRUE;
                        result->exception_code = code;
                        result->crash_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;
                        
                        // Generate description
                        sprintf_s(result->description, sizeof(result->description),
                                 "Exception 0x%08X at 0x%p", code, result->crash_address);
                        
                        process_crashed = TRUE;
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                break;
                
            case EXIT_PROCESS_DEBUG_EVENT:
                // Process exited
                if (!process_crashed) {
                    DWORD exit_code = debug_event.u.ExitProcess.dwExitCode;
                    if (exit_code != 0 && exit_code != 0xDEADBEEF) {
                        // Abnormal exit
                        result->crashed = TRUE;
                        result->exception_code = exit_code;
                        sprintf_s(result->description, sizeof(result->description),
                                 "Process exited with code 0x%08X", exit_code);
                    }
                }
                goto cleanup;
                
            case OUTPUT_DEBUG_STRING_EVENT:
                // Capture debug strings if needed
                break;
        }
        
        // Continue debugging
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status);
        
        if (process_crashed) {
            break;
        }
    }
    
cleanup:
    // Ensure process is terminated
    TerminateProcess(pi.hProcess, 0);
    
    // Wait for process to exit
    WaitForSingleObject(pi.hProcess, 1000);
    
    // Cleanup
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileA(temp_file);
    
    return TRUE;
}

// Run fuzzing campaign
VOID RunFuzzingCampaign(PFUZZ_CONTEXT ctx, LPCSTR loader_path, DWORD iterations) {
    LogMessage(ctx, "Starting fuzzing campaign with %d iterations", iterations);
    LogMessage(ctx, "Target loader: %s", loader_path);
    LogMessage(ctx, "Strategy: %d", ctx->strategy);
    
    // Create crashes directory
    CreateDirectoryA("crashes", NULL);
    
    for (DWORD i = 0; i < iterations; i++) {
        // Show progress
        if (i % 100 == 0) {
            printf("\r[*] Progress: %d/%d (Crashes: %d)", i, iterations, ctx->crash_count);
            fflush(stdout);
        }
        
        // Mutate PE
        if (!MutatePE(ctx, MUT_RANDOM_BYTES)) {
            LogMessage(ctx, "Failed to mutate PE at iteration %d", i);
            continue;
        }
        
        // Test with mutated PE
        TEST_RESULT result = {0};
        SetCrashContext(ctx, &result);
        
        if (!TestLoader(loader_path, ctx->mutated_pe, ctx->mutated_size, &result)) {
            LogMessage(ctx, "Failed to test loader at iteration %d", i);
            continue;
        }
        
        // Check for crash
        if (result.crashed) {
            LogCrash(ctx, &result);
            printf("\n[!] CRASH: %s\n", result.description);
        }
    }
    
    printf("\r[*] Progress: %d/%d (Crashes: %d) - Complete!\n", 
           iterations, iterations, ctx->crash_count);
} 