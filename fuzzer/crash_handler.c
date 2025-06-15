#include "include/fuzzer.h"
#include <dbghelp.h>
#include <stdarg.h>

#pragma comment(lib, "dbghelp.lib")

// Global crash context
static PFUZZ_CONTEXT g_fuzz_ctx = NULL;
static PTEST_RESULT g_test_result = NULL;

// Vectored exception handler
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (g_test_result) {
        g_test_result->crashed = TRUE;
        g_test_result->exception_code = ExceptionInfo->ExceptionRecord->ExceptionCode;
        g_test_result->crash_address = ExceptionInfo->ExceptionRecord->ExceptionAddress;
        
        // Generate description
        switch (ExceptionInfo->ExceptionRecord->ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION:
                sprintf_s(g_test_result->description, sizeof(g_test_result->description),
                         "Access violation at 0x%p", g_test_result->crash_address);
                break;
            case EXCEPTION_STACK_OVERFLOW:
                sprintf_s(g_test_result->description, sizeof(g_test_result->description),
                         "Stack overflow at 0x%p", g_test_result->crash_address);
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                sprintf_s(g_test_result->description, sizeof(g_test_result->description),
                         "Integer divide by zero at 0x%p", g_test_result->crash_address);
                break;
            default:
                sprintf_s(g_test_result->description, sizeof(g_test_result->description),
                         "Exception 0x%08X at 0x%p", 
                         g_test_result->exception_code, g_test_result->crash_address);
                break;
        }
        
        // Generate crash dump if context available
        if (g_fuzz_ctx) {
            GenerateCrashDump(ExceptionInfo);
        }
    }
    
    // Continue search for other handlers
    return EXCEPTION_CONTINUE_SEARCH;
}

// Setup crash handler
BOOL SetupCrashHandler(void) {
    // Add vectored exception handler
    if (!AddVectoredExceptionHandler(1, VectoredExceptionHandler)) {
        return FALSE;
    }
    
    // Set error mode to catch all errors
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    
    return TRUE;
}

// Generate minidump
VOID GenerateCrashDump(PEXCEPTION_POINTERS exception_info) {
    CHAR dump_path[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // Create dumps directory
    CreateDirectoryA("dumps", NULL);
    
    // Generate unique dump filename
    sprintf_s(dump_path, sizeof(dump_path), 
             "dumps\\crash_%04d%02d%02d_%02d%02d%02d_%08X.dmp",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
             exception_info->ExceptionRecord->ExceptionCode);
    
    // Create dump file
    HANDLE hDumpFile = CreateFileA(dump_path, GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDumpFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = exception_info;
        mdei.ClientPointers = FALSE;
        
        // Write minidump
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
                         hDumpFile, MiniDumpNormal, &mdei, NULL, NULL);
        
        CloseHandle(hDumpFile);
        
        // Log dump creation
        if (g_fuzz_ctx) {
            LogMessage(g_fuzz_ctx, "Created crash dump: %s", dump_path);
        }
    }
}

// Log message to file
VOID LogMessage(PFUZZ_CONTEXT ctx, LPCSTR format, ...) {
    if (!ctx || ctx->log_file == INVALID_HANDLE_VALUE) {
        return;
    }
    
    CHAR buffer[1024];
    va_list args;
    va_start(args, format);
    
    // Format timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);
    int len = sprintf_s(buffer, sizeof(buffer), "[%02d:%02d:%02d] ",
                       st.wHour, st.wMinute, st.wSecond);
    
    // Format message
    len += vsprintf_s(buffer + len, sizeof(buffer) - len, format, args);
    len += sprintf_s(buffer + len, sizeof(buffer) - len, "\r\n");
    
    va_end(args);
    
    // Write to log file
    DWORD written;
    WriteFile(ctx->log_file, buffer, len, &written, NULL);
    FlushFileBuffers(ctx->log_file);
}

// Log crash details
VOID LogCrash(PFUZZ_CONTEXT ctx, PTEST_RESULT result) {
    if (!ctx || !result || !result->crashed) {
        return;
    }
    
    ctx->crash_count++;
    
    LogMessage(ctx, "=== CRASH DETECTED ===");
    LogMessage(ctx, "Mutation #%d", ctx->mutation_count);
    LogMessage(ctx, "Exception: 0x%08X", result->exception_code);
    LogMessage(ctx, "Address: 0x%p", result->crash_address);
    LogMessage(ctx, "Description: %s", result->description);
    LogMessage(ctx, "Strategy: %d", ctx->strategy);
    LogMessage(ctx, "===================");
    
    // Save crash sample
    CHAR crash_file[MAX_PATH];
    sprintf_s(crash_file, sizeof(crash_file), "crashes\\crash_%d_%08X.bin",
             ctx->crash_count, result->exception_code);
    SaveMutatedPE(ctx, crash_file);
    
    LogMessage(ctx, "Saved crash sample: %s", crash_file);
}

// Set global context for crash handler
VOID SetCrashContext(PFUZZ_CONTEXT ctx, PTEST_RESULT result) {
    g_fuzz_ctx = ctx;
    g_test_result = result;
} 