#ifndef STEALTH_ASM_H
#define STEALTH_ASM_H

#include "common_defines.h"

// ========================================================================
// PHANTOM EDGE ASSEMBLY STEALTH OPERATIONS
// C Interface for Assembly Evil Genius Functions
// ========================================================================

#ifdef __cplusplus
extern "C" {
#endif

// ========================================================================
// ASSEMBLY FUNCTION DECLARATIONS
// ========================================================================

// Stealth memory operations with obfuscation
extern NTSTATUS stealth_memcpy(PVOID dest, PVOID src, SIZE_T size, BYTE xor_key);
extern NTSTATUS stealth_memset(PVOID dest, BYTE value, SIZE_T size, DWORD pattern);

// Direct syscall invocation with anti-debug
extern NTSTATUS direct_syscall(DWORD ssn, ...);

// Anti-debug detection functions
extern BOOL detect_hardware_breakpoints(VOID);

// High-performance entropy generation
extern DWORD generate_entropy(VOID);

// Stealth thread and memory operations
extern NTSTATUS stealth_create_thread(HANDLE process, PVOID start_addr, PVOID param, PHANDLE thread_handle);
extern NTSTATUS stealth_protect_memory(HANDLE process, PVOID address, SIZE_T size, DWORD protection, PDWORD old_protection);

// Obfuscated function calls
extern PVOID obfuscated_call(PVOID function_ptr, PVOID arg1, PVOID arg2, PVOID arg3);

// ========================================================================
// C WRAPPER FUNCTIONS AND UTILITIES
// ========================================================================

// High-level stealth memory copy wrapper
static inline NTSTATUS StealthMemoryCopy(PVOID dest, PVOID src, SIZE_T size) {
    // Generate random XOR key for this operation
    BYTE xor_key = (BYTE)(generate_entropy() & 0xFF);
    return stealth_memcpy(dest, src, size, xor_key);
}

// High-level stealth memory set wrapper
static inline NTSTATUS StealthMemorySet(PVOID dest, BYTE value, SIZE_T size) {
    // Generate random pattern for obfuscation
    DWORD pattern = generate_entropy();
    return stealth_memset(dest, value, size, pattern);
}

// Safe syscall wrapper with anti-debug checks
static inline NTSTATUS SafeSyscall(DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4) {
    // Check for debugging before syscall
    if (detect_hardware_breakpoints()) {
        return STATUS_DEBUGGER_INACTIVE;
    }
    
    // Perform syscall through assembly stub
    return direct_syscall(ssn, arg1, arg2, arg3, arg4);
}

// ========================================================================
// PERFORMANCE OPTIMIZED MEMORY OPERATIONS
// ========================================================================

// Assembly-optimized memory operations selector
typedef enum _STEALTH_OPERATION_TYPE {
    STEALTH_OP_COPY = 0,
    STEALTH_OP_SET,
    STEALTH_OP_COMPARE,
    STEALTH_OP_SEARCH
} STEALTH_OPERATION_TYPE;

// Performance metrics for assembly operations
typedef struct _STEALTH_PERFORMANCE_METRICS {
    DWORD operations_count;
    DWORD total_bytes_processed;
    DWORD average_time_microseconds;
    DWORD debug_detections;
    DWORD entropy_generated;
} STEALTH_PERFORMANCE_METRICS, *PSTEALTH_PERFORMANCE_METRICS;

// ========================================================================
// ASSEMBLY INTEGRATION HELPERS
// ========================================================================

// Initialize assembly stealth operations
BOOL StealthAsm_Initialize(VOID);

// Get performance metrics
VOID StealthAsm_GetMetrics(PSTEALTH_PERFORMANCE_METRICS metrics);

// Reset performance counters
VOID StealthAsm_ResetMetrics(VOID);

// Validate assembly function availability
BOOL StealthAsm_ValidateFunctions(VOID);

// ========================================================================
// ANTI-DEBUG INTEGRATION
// ========================================================================

// Comprehensive anti-debug check using assembly functions
BOOL StealthAsm_IsDebuggingDetected(VOID);

// Clear debug registers (if possible)
NTSTATUS StealthAsm_ClearDebugRegisters(VOID);

// Check for common debugger artifacts
BOOL StealthAsm_DetectDebuggerArtifacts(VOID);

// ========================================================================
// ENTROPY AND RANDOMIZATION
// ========================================================================

// Generate cryptographically strong randomness using assembly
DWORD StealthAsm_GenerateStrongEntropy(PVOID buffer, SIZE_T size);

// Get high-resolution timing for entropy
LARGE_INTEGER StealthAsm_GetHighResTiming(VOID);

// XOR key generation for obfuscation
static inline BYTE StealthAsm_GenerateXORKey(VOID) {
    return (BYTE)(generate_entropy() & 0xFF);
}

// ========================================================================
// SYSCALL INTEGRATION WITH HALO'S GATE
// ========================================================================

// Forward declarations for integration
struct _RTLDR_CTX;
struct _HALO_GATE_CTX;

// Integrate assembly syscalls with Halo's Gate
NTSTATUS StealthAsm_IntegrateWithHaloGate(struct _RTLDR_CTX* ctx, struct _HALO_GATE_CTX* halo_ctx);

// Enhanced syscall with SSN resolution
NTSTATUS StealthAsm_EnhancedSyscall(struct _RTLDR_CTX* ctx, PCSTR function_name, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4);

// Batch syscall operations for performance
NTSTATUS StealthAsm_BatchSyscalls(struct _RTLDR_CTX* ctx, DWORD operation_count, PVOID* operations);

// ========================================================================
// MEMORY PROTECTION AND THREAD OPERATIONS
// ========================================================================

// Enhanced thread creation with full stealth
NTSTATUS StealthAsm_CreateStealthThread(
    struct _RTLDR_CTX* ctx,
    HANDLE target_process,
    PVOID start_address,
    PVOID parameter,
    DWORD creation_flags,
    PHANDLE thread_handle
);

// Enhanced memory protection with anti-detection
NTSTATUS StealthAsm_ProtectMemoryAdvanced(
    struct _RTLDR_CTX* ctx,
    HANDLE process,
    PVOID address,
    SIZE_T size,
    DWORD new_protection,
    PDWORD old_protection
);

// Memory allocation with stealth characteristics
NTSTATUS StealthAsm_AllocateStealthMemory(
    struct _RTLDR_CTX* ctx,
    HANDLE process,
    PVOID* base_address,
    SIZE_T size,
    DWORD allocation_type,
    DWORD protection
);

// ========================================================================
// OBFUSCATED EXECUTION HELPERS
// ========================================================================

// Execute function through obfuscated assembly call
PVOID StealthAsm_ExecuteObfuscated(PVOID function_ptr, DWORD arg_count, ...);

// Create obfuscated function pointer
PVOID StealthAsm_ObfuscateFunctionPointer(PVOID original_ptr, DWORD obfuscation_key);

// Deobfuscate function pointer for execution
PVOID StealthAsm_DeobfuscateFunctionPointer(PVOID obfuscated_ptr, DWORD obfuscation_key);

// ========================================================================
// ASSEMBLY OPERATION STATISTICS
// ========================================================================

// Track assembly operation performance
VOID StealthAsm_TrackOperation(STEALTH_OPERATION_TYPE op_type, SIZE_T bytes_processed, DWORD time_microseconds);

// Get operation statistics
VOID StealthAsm_GetOperationStats(STEALTH_OPERATION_TYPE op_type, PDWORD avg_time, PDWORD total_ops);

// Cleanup assembly resources
VOID StealthAsm_Cleanup(VOID);

#ifdef __cplusplus
}
#endif

#endif // STEALTH_ASM_H 