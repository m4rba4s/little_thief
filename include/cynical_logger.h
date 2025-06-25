#ifndef CYNICAL_LOGGER_H
#define CYNICAL_LOGGER_H

#include "common_defines.h"

// ========================================================================
// CYNICAL LOGGER v1.0 - "Because Your Failures Need Documentation"
// "Don't be a noob, log like a pro or go home crying" - Elite Logger
// ========================================================================

// Log levels with attitude
typedef enum _CYNICAL_LOG_LEVEL {
    CYNICAL_DEBUG = 0,    // "Oh, you want EVERY detail? Here's your precious debug info, script kiddie"
    CYNICAL_INFO = 1,     // "Basic information for those who can actually read"
    CYNICAL_WARN = 2,     // "Warning: You're about to fuck up (again)"
    CYNICAL_ERROR = 3,    // "Congratulations! You broke something. Achievement unlocked!"
    CYNICAL_CRITICAL = 4, // "DEFCON 1: The shit has hit the fan. Time to panic."
    CYNICAL_STEALTH = 5   // "Silent mode - because sometimes even logs need to STFU"
} CYNICAL_LOG_LEVEL;

// Auto-cleanup triggers
typedef enum _CLEANUP_TRIGGER {
    CLEANUP_TIMER = 1,     // Time-based cleanup
    CLEANUP_SIZE = 2,      // Size-based cleanup  
    CLEANUP_DETECTION = 4, // EDR detection trigger
    CLEANUP_MANUAL = 8,    // Manual trigger
    CLEANUP_PANIC = 16     // Emergency self-destruct
} CLEANUP_TRIGGER;

// Cynical messages structure
typedef struct _CYNICAL_MESSAGE {
    const char* debug_insult;
    const char* info_advice; 
    const char* warn_threat;
    const char* error_mockery;
    const char* critical_panic;
} CYNICAL_MESSAGE, *PCYNICAL_MESSAGE;

// Logger configuration
typedef struct _CYNICAL_CONFIG {
    CYNICAL_LOG_LEVEL min_level;
    BOOL enable_timestamps;
    BOOL enable_sarcasm;
    BOOL enable_technical_details;
    BOOL enable_auto_cleanup;
    DWORD cleanup_timer_minutes;
    SIZE_T max_log_size_mb;
    CLEANUP_TRIGGER cleanup_triggers;
    char log_file_path[MAX_PATH];
} CYNICAL_CONFIG, *PCYNICAL_CONFIG;

// Logger context
typedef struct _CYNICAL_LOGGER_CTX {
    CYNICAL_CONFIG config;
    HANDLE log_file_handle;
    CRITICAL_SECTION log_mutex;
    LARGE_INTEGER start_time;
    SIZE_T current_log_size;
    BOOL is_initialized;
    DWORD session_id;
    char session_name[64];
} CYNICAL_LOGGER_CTX, *PCYNICAL_LOGGER_CTX;

// Global logger instance
extern CYNICAL_LOGGER_CTX g_cynical_logger;

// ========================================================================
// CYNICAL LOGGER API - "Use it or lose it, your choice kiddo"
// ========================================================================

// Initialize the cynical logger
BOOL CynicalLogger_Initialize(PCYNICAL_CONFIG config);

// Shutdown and cleanup
VOID CynicalLogger_Shutdown(BOOL force_cleanup);

// Main logging functions with attitude
VOID CynicalLog_Debug(const char* component, const char* format, ...);
VOID CynicalLog_Info(const char* component, const char* format, ...);
VOID CynicalLog_Warn(const char* component, const char* format, ...);
VOID CynicalLog_Error(const char* component, const char* format, ...);
VOID CynicalLog_Critical(const char* component, const char* format, ...);

// Specialized logging functions
VOID CynicalLog_SyscallAttempt(const char* syscall_name, DWORD syscall_id, NTSTATUS result);
VOID CynicalLog_InjectionAttempt(const char* technique, const char* target_process, NTSTATUS result);
VOID CynicalLog_EDRDetection(const char* edr_name, const char* detection_method, BOOL detected);
VOID CynicalLog_EvasionTechnique(const char* technique, const char* target, BOOL success);

// Auto-cleanup functions
VOID CynicalLogger_TriggerCleanup(CLEANUP_TRIGGER trigger);
BOOL CynicalLogger_IsCleanupNeeded(void);
VOID CynicalLogger_SelfDestruct(const char* reason);

// Utility functions
VOID CynicalLogger_SetSessionName(const char* session_name);
VOID CynicalLogger_DumpSystemInfo(void);
VOID CynicalLogger_LogMemoryLayout(PVOID base_address, SIZE_T size, const char* description);

// ========================================================================
// CYNICAL MESSAGES DATABASE - "Sarcasm Powered by Technical Excellence"
// ========================================================================

// Predefined cynical messages for different scenarios
extern const CYNICAL_MESSAGE CYNICAL_MSG_SYSCALL_RESOLUTION;
extern const CYNICAL_MESSAGE CYNICAL_MSG_INJECTION_ATTEMPT;
extern const CYNICAL_MESSAGE CYNICAL_MSG_EDR_DETECTION;
extern const CYNICAL_MESSAGE CYNICAL_MSG_EVASION_TECHNIQUE;
extern const CYNICAL_MESSAGE CYNICAL_MSG_MEMORY_ALLOCATION;
extern const CYNICAL_MESSAGE CYNICAL_MSG_PROCESS_MANIPULATION;
extern const CYNICAL_MESSAGE CYNICAL_MSG_THREAD_OPERATIONS;
extern const CYNICAL_MESSAGE CYNICAL_MSG_FILE_OPERATIONS;
extern const CYNICAL_MESSAGE CYNICAL_MSG_REGISTRY_OPERATIONS;
extern const CYNICAL_MESSAGE CYNICAL_MSG_NETWORK_OPERATIONS;

// Convenience macros for common logging patterns
#define CYNICAL_SYSCALL_LOG(name, id, result) \
    CynicalLog_SyscallAttempt(name, id, result)

#define CYNICAL_INJECTION_LOG(technique, target, result) \
    CynicalLog_InjectionAttempt(technique, target, result)

#define CYNICAL_EDR_LOG(edr, method, detected) \
    CynicalLog_EDRDetection(edr, method, detected)

#define CYNICAL_EVASION_LOG(technique, target, success) \
    CynicalLog_EvasionTechnique(technique, target, success)

// Debug helpers with attitude
#ifdef _DEBUG
#define CYNICAL_DBG(component, format, ...) \
    CynicalLog_Debug(component, format, __VA_ARGS__)
#else
#define CYNICAL_DBG(component, format, ...) ((void)0)
#endif

// Error handling with cynicism
#define CYNICAL_CHECK_STATUS(status, component, operation) \
    do { \
        if (!NT_SUCCESS(status)) { \
            CynicalLog_Error(component, "Operation '%s' failed with status 0x%08X. " \
                           "Don't blame the code, blame your understanding of it.", \
                           operation, status); \
        } \
    } while(0)

#endif // CYNICAL_LOGGER_H 