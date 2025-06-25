#include "../include/cynical_logger.h"
#include "../include/syscalls.h"
#include "../include/utils.h"
#include "../include/mem.h"
#include <stdarg.h>

// ========================================================================
// CYNICAL LOGGER v1.0 IMPLEMENTATION - "Your Failures, Documented in Style"
// ========================================================================

// Global logger instance
CYNICAL_LOGGER_CTX g_cynical_logger = { 0 };

// Predefined cynical messages database
const CYNICAL_MESSAGE CYNICAL_MSG_SYSCALL_RESOLUTION = {
    .debug_insult = "Syscall resolution attempt - let's see if you can do this without breaking everything",
    .info_advice = "Syscall resolved successfully. Congrats, you did something right for once",
    .warn_threat = "Syscall resolution warning - your code is walking on thin ice",
    .error_mockery = "Syscall resolution failed. Did you even test this garbage?",
    .critical_panic = "CRITICAL: Syscall resolution catastrophic failure. Time to find a new career"
};

const CYNICAL_MESSAGE CYNICAL_MSG_INJECTION_ATTEMPT = {
    .debug_insult = "Injection attempt in progress - trying to play god with process memory, I see",
    .info_advice = "Injection successful. Even a broken clock is right twice a day",
    .warn_threat = "Injection warning - EDRs are watching you, amateur",
    .error_mockery = "Injection failed. Your technique is as subtle as a brick through a window",
    .critical_panic = "CRITICAL: Injection disaster. You just triggered every EDR on the planet"
};

const CYNICAL_MESSAGE CYNICAL_MSG_EDR_DETECTION = {
    .debug_insult = "EDR detection scan - let's see if you're as stealthy as you think",
    .info_advice = "EDR status confirmed. Knowledge is power, use it wisely",
    .warn_threat = "EDR detection warning - you're being watched, script kiddie",
    .error_mockery = "EDR detection failed. Your reconnaissance skills need serious work",
    .critical_panic = "CRITICAL: EDR detection failure. You're flying blind into enemy territory"
};

const CYNICAL_MESSAGE CYNICAL_MSG_EVASION_TECHNIQUE = {
    .debug_insult = "Evasion technique deployment - let's see your ninja skills in action",
    .info_advice = "Evasion technique successful. You might actually survive this operation",
    .warn_threat = "Evasion technique warning - your stealth is slipping",
    .error_mockery = "Evasion technique failed. You're about as stealthy as a marching band",
    .critical_panic = "CRITICAL: Evasion failure. You just lit up every security dashboard"
};

const CYNICAL_MESSAGE CYNICAL_MSG_MEMORY_ALLOCATION = {
    .debug_insult = "Memory allocation request - trying to reserve space for your mistakes",
    .info_advice = "Memory allocated successfully. Don't waste it on stupid operations",
    .warn_threat = "Memory allocation warning - you're running low on resources",
    .error_mockery = "Memory allocation failed. Even the OS doesn't trust your code",
    .critical_panic = "CRITICAL: Memory allocation disaster. Your payload is dead in the water"
};

const CYNICAL_MESSAGE CYNICAL_MSG_PROCESS_MANIPULATION = {
    .debug_insult = "Process manipulation attempt - playing puppet master with system processes",
    .info_advice = "Process manipulation successful. Power corrupts, use it responsibly",
    .warn_threat = "Process manipulation warning - you're poking the security bear",
    .error_mockery = "Process manipulation failed. The OS just laughed at your pathetic attempt",
    .critical_panic = "CRITICAL: Process manipulation catastrophe. You broke the entire system"
};

const CYNICAL_MESSAGE CYNICAL_MSG_THREAD_OPERATIONS = {
    .debug_insult = "Thread operation requested - let's see if you understand concurrency",
    .info_advice = "Thread operation completed. Threading done right for once",
    .warn_threat = "Thread operation warning - race conditions are your enemy",
    .error_mockery = "Thread operation failed. Your threading skills are thread-bare",
    .critical_panic = "CRITICAL: Thread operation disaster. You just deadlocked everything"
};

const CYNICAL_MESSAGE CYNICAL_MSG_FILE_OPERATIONS = {
    .debug_insult = "File operation initiated - trying to touch the filesystem like a pro",
    .info_advice = "File operation successful. File I/O done competently",
    .warn_threat = "File operation warning - leaving forensic traces like breadcrumbs",
    .error_mockery = "File operation failed. The filesystem rejected your amateur code",
    .critical_panic = "CRITICAL: File operation catastrophe. You corrupted something important"
};

const CYNICAL_MESSAGE CYNICAL_MSG_REGISTRY_OPERATIONS = {
    .debug_insult = "Registry operation attempt - messing with Windows' brain, bold move",
    .info_advice = "Registry operation successful. Registry manipulation done right",
    .warn_threat = "Registry operation warning - Windows is keeping track of your changes",
    .error_mockery = "Registry operation failed. Even the registry doesn't want your data",
    .critical_panic = "CRITICAL: Registry operation disaster. You broke Windows configuration"
};

const CYNICAL_MESSAGE CYNICAL_MSG_NETWORK_OPERATIONS = {
    .debug_insult = "Network operation requested - trying to phone home like E.T.",
    .info_advice = "Network operation successful. Network communication established",
    .warn_threat = "Network operation warning - network admins are watching traffic",
    .error_mockery = "Network operation failed. Your packets got lost in cyberspace",
    .critical_panic = "CRITICAL: Network operation disaster. You triggered network security alerts"
};

// ========================================================================
// NO-CRT UTILITY FUNCTIONS
// ========================================================================

// No-CRT string length
static SIZE_T nocrt_strlen(const char* str) {
    SIZE_T len = 0;
    if (!str) return 0;
    while (str[len]) len++;
    return len;
}

// No-CRT string copy
static void nocrt_strcpy(char* dest, const char* src, SIZE_T dest_size) {
    SIZE_T i = 0;
    if (!dest || !src || dest_size == 0) return;
    
    while (src[i] && i < (dest_size - 1)) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

// No-CRT sprintf implementation
static int nocrt_sprintf(char* buffer, SIZE_T buffer_size, const char* format, ...) {
    if (!buffer || !format || buffer_size == 0) return 0;
    
    va_list args;
    va_start(args, format);
    
    // Use Windows API wvsprintfA which doesn't require CRT
    int result = wvsprintfA(buffer, format, args);
    
    va_end(args);
    
    // Ensure null termination and bounds
    if (result >= 0 && (SIZE_T)result < buffer_size) {
        buffer[result] = '\0';
    } else {
        buffer[buffer_size - 1] = '\0';
        result = (int)(buffer_size - 1);
    }
    
    return result;
}

// No-CRT vsprintf implementation
static int nocrt_vsprintf(char* buffer, SIZE_T buffer_size, const char* format, va_list args) {
    if (!buffer || !format || buffer_size == 0) return 0;
    
    // Use Windows API wvsprintfA which doesn't require CRT
    int result = wvsprintfA(buffer, format, args);
    
    // Ensure null termination and bounds
    if (result >= 0 && (SIZE_T)result < buffer_size) {
        buffer[result] = '\0';
    } else {
        buffer[buffer_size - 1] = '\0';
        result = (int)(buffer_size - 1);
    }
    
    return result;
}

// ========================================================================
// INTERNAL HELPER FUNCTIONS
// ========================================================================

static void CynicalLogger_WriteToFile(const char* message, SIZE_T length) {
    if (!g_cynical_logger.log_file_handle || g_cynical_logger.log_file_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    NTSTATUS status;
    IO_STATUS_BLOCK iosb = { 0 };
    
    status = wrapped_NtWriteFile(
        g_cynical_logger.log_file_handle,
        NULL,
        NULL,
        NULL,
        &iosb,
        (PVOID)message,
        (ULONG)length,
        NULL,
        NULL
    );

    if (NT_SUCCESS(status)) {
        g_cynical_logger.current_log_size += length;
    }
}

static void CynicalLogger_GetTimestamp(char* buffer, SIZE_T buffer_size) {
    if (!g_cynical_logger.config.enable_timestamps) {
        buffer[0] = '\0';
        return;
    }

    LARGE_INTEGER current_time;
    wrapped_NtQuerySystemTime(&current_time);
    
    // Simple timestamp format: [HHMMSS]
    ULONGLONG seconds = (current_time.QuadPart - g_cynical_logger.start_time.QuadPart) / 10000000ULL;
    DWORD hours = (DWORD)(seconds / 3600);
    DWORD minutes = (DWORD)((seconds % 3600) / 60);
    DWORD secs = (DWORD)(seconds % 60);
    
    nocrt_sprintf(buffer, buffer_size, "[%02d%02d%02d] ", hours % 24, minutes, secs);
}

static const char* CynicalLogger_GetLevelString(CYNICAL_LOG_LEVEL level) {
    switch (level) {
        case CYNICAL_DEBUG: return "DBG";
        case CYNICAL_INFO: return "INF";
        case CYNICAL_WARN: return "WRN";
        case CYNICAL_ERROR: return "ERR";
        case CYNICAL_CRITICAL: return "CRT";
        case CYNICAL_STEALTH: return "STL";
        default: return "UNK";
    }
}

static void CynicalLogger_FormatMessage(
    char* output_buffer,
    SIZE_T buffer_size,
    CYNICAL_LOG_LEVEL level,
    const char* component,
    const char* message,
    const char* cynical_addon
) {
    char timestamp[32] = { 0 };
    CynicalLogger_GetTimestamp(timestamp, sizeof(timestamp));
    
    const char* level_str = CynicalLogger_GetLevelString(level);
    
    if (g_cynical_logger.config.enable_sarcasm && cynical_addon) {
        nocrt_sprintf(output_buffer, buffer_size,
            "%s[%s][%s] %s | %s\r\n",
            timestamp, level_str, component, message, cynical_addon);
    } else {
        nocrt_sprintf(output_buffer, buffer_size,
            "%s[%s][%s] %s\r\n",
            timestamp, level_str, component, message);
    }
}

static void CynicalLogger_LogInternal(
    CYNICAL_LOG_LEVEL level,
    const char* component,
    const char* format,
    va_list args,
    const CYNICAL_MESSAGE* cynical_msg
) {
    if (!g_cynical_logger.is_initialized || level < g_cynical_logger.config.min_level) {
        return;
    }

    // Enter critical section for thread safety
    EnterCriticalSection(&g_cynical_logger.log_mutex);

    char message_buffer[1024] = { 0 };
    char output_buffer[1536] = { 0 };
    
    // Format the main message
    nocrt_vsprintf(message_buffer, sizeof(message_buffer), format, args);
    
    // Get cynical addon based on level
    const char* cynical_addon = NULL;
    if (cynical_msg && g_cynical_logger.config.enable_sarcasm) {
        switch (level) {
            case CYNICAL_DEBUG: cynical_addon = cynical_msg->debug_insult; break;
            case CYNICAL_INFO: cynical_addon = cynical_msg->info_advice; break;
            case CYNICAL_WARN: cynical_addon = cynical_msg->warn_threat; break;
            case CYNICAL_ERROR: cynical_addon = cynical_msg->error_mockery; break;
            case CYNICAL_CRITICAL: cynical_addon = cynical_msg->critical_panic; break;
        }
    }
    
    // Format final output
    CynicalLogger_FormatMessage(output_buffer, sizeof(output_buffer),
                               level, component, message_buffer, cynical_addon);
    
    // Write to file
    CynicalLogger_WriteToFile(output_buffer, nocrt_strlen(output_buffer));
    
    // Check if cleanup is needed
    if (CynicalLogger_IsCleanupNeeded()) {
        CynicalLogger_TriggerCleanup(CLEANUP_SIZE);
    }
    
    LeaveCriticalSection(&g_cynical_logger.log_mutex);
}

// ========================================================================
// PUBLIC API IMPLEMENTATION
// ========================================================================

BOOL CynicalLogger_Initialize(PCYNICAL_CONFIG config) {
    if (g_cynical_logger.is_initialized) {
        return TRUE; // Already initialized
    }

    // Copy configuration
    if (config) {
        memcpy(&g_cynical_logger.config, config, sizeof(CYNICAL_CONFIG));
    } else {
        // Default configuration
        g_cynical_logger.config.min_level = CYNICAL_INFO;
        g_cynical_logger.config.enable_timestamps = TRUE;
        g_cynical_logger.config.enable_sarcasm = TRUE;
        g_cynical_logger.config.enable_technical_details = TRUE;
        g_cynical_logger.config.enable_auto_cleanup = TRUE;
        g_cynical_logger.config.cleanup_timer_minutes = 30;
        g_cynical_logger.config.max_log_size_mb = 10;
        g_cynical_logger.config.cleanup_triggers = CLEANUP_TIMER | CLEANUP_SIZE;
        nocrt_strcpy(g_cynical_logger.config.log_file_path, "phantom_edge.log", MAX_PATH);
    }

    // Initialize critical section
    InitializeCriticalSection(&g_cynical_logger.log_mutex);

    // Generate session ID
    wrapped_NtQuerySystemTime(&g_cynical_logger.start_time);
    g_cynical_logger.session_id = (DWORD)(g_cynical_logger.start_time.LowPart & 0xFFFFFF);
    
    // Set default session name
    nocrt_sprintf(g_cynical_logger.session_name, sizeof(g_cynical_logger.session_name),
               "PhantomEdge_%06X", g_cynical_logger.session_id);

    // Create/open log file
    UNICODE_STRING log_file_name;
    WCHAR wide_path[MAX_PATH];
    
    MultiByteToWideChar(CP_ACP, 0, g_cynical_logger.config.log_file_path, -1,
                       wide_path, MAX_PATH);
    
    RtlInitUnicodeString(&log_file_name, wide_path);
    
    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, &log_file_name,
                              OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    IO_STATUS_BLOCK iosb = { 0 };
    NTSTATUS status = wrapped_NtCreateFile(
        &g_cynical_logger.log_file_handle,
        GENERIC_WRITE | SYNCHRONIZE,
        &obj_attr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DeleteCriticalSection(&g_cynical_logger.log_mutex);
        return FALSE;
    }

    g_cynical_logger.current_log_size = 0;
    g_cynical_logger.is_initialized = TRUE;

    // Log initialization
    CynicalLog_Info("LOGGER", "Cynical Logger v1.0 initialized - Session: %s",
                   g_cynical_logger.session_name);

    return TRUE;
}

VOID CynicalLogger_Shutdown(BOOL force_cleanup) {
    if (!g_cynical_logger.is_initialized) {
        return;
    }

    EnterCriticalSection(&g_cynical_logger.log_mutex);

    // Log shutdown
    CynicalLog_Info("LOGGER", "Cynical Logger shutting down - Session: %s completed",
                   g_cynical_logger.session_name);

    // Close log file
    if (g_cynical_logger.log_file_handle && 
        g_cynical_logger.log_file_handle != INVALID_HANDLE_VALUE) {
        wrapped_NtClose(g_cynical_logger.log_file_handle);
        g_cynical_logger.log_file_handle = NULL;
    }

    // Force cleanup if requested
    if (force_cleanup) {
        CynicalLogger_SelfDestruct("Forced cleanup on shutdown");
    }

    LeaveCriticalSection(&g_cynical_logger.log_mutex);
    DeleteCriticalSection(&g_cynical_logger.log_mutex);

    // Clear context
    memset(&g_cynical_logger, 0, sizeof(CYNICAL_LOGGER_CTX));
}

VOID CynicalLog_Debug(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    CynicalLogger_LogInternal(CYNICAL_DEBUG, component, format, args, NULL);
    va_end(args);
}

VOID CynicalLog_Info(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    CynicalLogger_LogInternal(CYNICAL_INFO, component, format, args, NULL);
    va_end(args);
}

VOID CynicalLog_Warn(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    CynicalLogger_LogInternal(CYNICAL_WARN, component, format, args, NULL);
    va_end(args);
}

VOID CynicalLog_Error(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    CynicalLogger_LogInternal(CYNICAL_ERROR, component, format, args, NULL);
    va_end(args);
}

VOID CynicalLog_Critical(const char* component, const char* format, ...) {
    va_list args;
    va_start(args, format);
    CynicalLogger_LogInternal(CYNICAL_CRITICAL, component, format, args, NULL);
    va_end(args);
}

VOID CynicalLog_SyscallAttempt(const char* syscall_name, DWORD syscall_id, NTSTATUS result) {
    char formatted_msg[512];
    
    if (NT_SUCCESS(result)) {
        nocrt_sprintf(formatted_msg, sizeof(formatted_msg),
            "Syscall %s (ID: 0x%X) executed successfully - Status: 0x%08X",
            syscall_name, syscall_id, result);
        
        va_list dummy_args;
        CynicalLogger_LogInternal(CYNICAL_INFO, "SYSCALL", formatted_msg, dummy_args, &CYNICAL_MSG_SYSCALL_RESOLUTION);
    } else {
        nocrt_sprintf(formatted_msg, sizeof(formatted_msg),
            "Syscall %s (ID: 0x%X) failed - Status: 0x%08X",
            syscall_name, syscall_id, result);
        
        va_list dummy_args;
        CynicalLogger_LogInternal(CYNICAL_ERROR, "SYSCALL", formatted_msg, dummy_args, &CYNICAL_MSG_SYSCALL_RESOLUTION);
    }
}

VOID CynicalLog_InjectionAttempt(const char* technique, const char* target_process, NTSTATUS result) {
    char formatted_msg[512];
    
    if (NT_SUCCESS(result)) {
        nocrt_sprintf(formatted_msg, sizeof(formatted_msg),
            "Injection technique '%s' succeeded on target '%s' - Status: 0x%08X",
            technique, target_process, result);
        
        va_list dummy_args;
        CynicalLogger_LogInternal(CYNICAL_INFO, "INJECTION", formatted_msg, dummy_args, &CYNICAL_MSG_INJECTION_ATTEMPT);
    } else {
        nocrt_sprintf(formatted_msg, sizeof(formatted_msg),
            "Injection technique '%s' failed on target '%s' - Status: 0x%08X",
            technique, target_process, result);
        
        va_list dummy_args;
        CynicalLogger_LogInternal(CYNICAL_ERROR, "INJECTION", formatted_msg, dummy_args, &CYNICAL_MSG_INJECTION_ATTEMPT);
    }
}

VOID CynicalLog_EDRDetection(const char* edr_name, const char* detection_method, BOOL detected) {
    char formatted_msg[512];
    
    if (detected) {
        nocrt_sprintf(formatted_msg, sizeof(formatted_msg),
            "EDR '%s' detected using method '%s'",
            edr_name, detection_method);
        
        va_list dummy_args;
        CynicalLogger_LogInternal(CYNICAL_WARN, "EDR", formatted_msg, dummy_args, &CYNICAL_MSG_EDR_DETECTION);
    } else {
        nocrt_sprintf(formatted_msg, sizeof(formatted_msg),
            "EDR '%s' not detected via method '%s'",
            edr_name, detection_method);
        
        va_list dummy_args;
        CynicalLogger_LogInternal(CYNICAL_INFO, "EDR", formatted_msg, dummy_args, &CYNICAL_MSG_EDR_DETECTION);
    }
}

VOID CynicalLog_EvasionTechnique(const char* technique, const char* target, BOOL success) {
    char formatted_msg[512];
    
    if (success) {
        nocrt_sprintf(formatted_msg, sizeof(formatted_msg),
            "Evasion technique '%s' successful on target '%s'",
            technique, target);
        
        va_list dummy_args;
        CynicalLogger_LogInternal(CYNICAL_INFO, "EVASION", formatted_msg, dummy_args, &CYNICAL_MSG_EVASION_TECHNIQUE);
    } else {
        nocrt_sprintf(formatted_msg, sizeof(formatted_msg),
            "Evasion technique '%s' failed on target '%s'",
            technique, target);
        
        va_list dummy_args;
        CynicalLogger_LogInternal(CYNICAL_ERROR, "EVASION", formatted_msg, dummy_args, &CYNICAL_MSG_EVASION_TECHNIQUE);
    }
}

VOID CynicalLogger_TriggerCleanup(CLEANUP_TRIGGER trigger) {
    if (!g_cynical_logger.is_initialized) {
        return;
    }

    CynicalLog_Warn("CLEANUP", "Cleanup triggered by: 0x%X", trigger);

    // Implement cleanup logic based on trigger
    if (trigger & CLEANUP_PANIC) {
        CynicalLogger_SelfDestruct("Panic cleanup triggered");
    }
}

BOOL CynicalLogger_IsCleanupNeeded(void) {
    if (!g_cynical_logger.config.enable_auto_cleanup) {
        return FALSE;
    }

    // Check size limit
    if (g_cynical_logger.config.cleanup_triggers & CLEANUP_SIZE) {
        SIZE_T max_size = g_cynical_logger.config.max_log_size_mb * 1024 * 1024;
        if (g_cynical_logger.current_log_size > max_size) {
            return TRUE;
        }
    }

    return FALSE;
}

VOID CynicalLogger_SelfDestruct(const char* reason) {
    CynicalLog_Critical("DESTRUCT", "Self-destruct initiated: %s", reason);
    
    // Close and delete log file
    if (g_cynical_logger.log_file_handle && 
        g_cynical_logger.log_file_handle != INVALID_HANDLE_VALUE) {
        wrapped_NtClose(g_cynical_logger.log_file_handle);
        g_cynical_logger.log_file_handle = NULL;
        
        // Delete the log file (using standard API for now)
        // TODO: Implement wrapped_NtDeleteFile for full syscall usage
        DeleteFileA(g_cynical_logger.config.log_file_path);
    }
}

VOID CynicalLogger_SetSessionName(const char* session_name) {
    if (session_name && nocrt_strlen(session_name) < sizeof(g_cynical_logger.session_name)) {
        nocrt_strcpy(g_cynical_logger.session_name, session_name, sizeof(g_cynical_logger.session_name));
        CynicalLog_Info("LOGGER", "Session name updated to: %s", session_name);
    }
}

VOID CynicalLogger_DumpSystemInfo(void) {
    CynicalLog_Info("SYSINFO", "System information dump initiated");
    CynicalLog_Info("SYSINFO", "Session ID: 0x%08X", g_cynical_logger.session_id);
    CynicalLog_Info("SYSINFO", "Session Name: %s", g_cynical_logger.session_name);
    CynicalLog_Info("SYSINFO", "Current log size: %zu bytes", g_cynical_logger.current_log_size);
}

VOID CynicalLogger_LogMemoryLayout(PVOID base_address, SIZE_T size, const char* description) {
    CynicalLog_Debug("MEMORY", "Memory layout: %s - Base: 0x%p, Size: 0x%zX", 
                     description, base_address, size);
} 