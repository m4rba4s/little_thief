#ifndef HALO_GATE_H
#define HALO_GATE_H

#include "common_defines.h"

// Forward declarations
struct _RTLDR_CTX;

// ========================================================================
// ELITE HALO'S GATE v2.0 - Advanced Syscall Resolution Engine
// Techniques: Halo's Gate + Tartarus Gate + Hell's Gate fallbacks
// Anti-Hook: Pattern reconstruction, neighbor analysis, disassembly
// ========================================================================

// Syscall resolution methods (priority order)
typedef enum _SYSCALL_RESOLUTION_METHOD {
    RESOLVE_METHOD_DIRECT = 0,      // Direct function analysis (ideal)
    RESOLVE_METHOD_HALO_GATE,       // Neighbor function analysis (hooked target)
    RESOLVE_METHOD_TARTARUS_GATE,   // Advanced unhook + re-analysis
    RESOLVE_METHOD_HELL_GATE,       // Manual .text section scanning
    RESOLVE_METHOD_FAILED           // All methods failed
} SYSCALL_RESOLUTION_METHOD;

// Enhanced syscall information
typedef struct _ELITE_SYSCALL_INFO {
    DWORD syscall_id;
    PVOID function_address;
    SYSCALL_RESOLUTION_METHOD resolution_method;
    BOOL is_hooked;
    BOOL is_valid;
    BYTE original_bytes[32];        // Original function bytes (for unhooking)
    BYTE current_bytes[32];         // Current function bytes (for hook detection)
} ELITE_SYSCALL_INFO, *PELITE_SYSCALL_INFO;

// Advanced hook detection patterns
typedef struct _HOOK_PATTERNS {
    BYTE jmp_rel32[5];              // E9 XX XX XX XX (relative jump)
    BYTE jmp_rax[2];                // FF E0 (jmp rax)
    BYTE mov_rax_jmp[12];           // 48 B8 XX XX XX XX XX XX XX XX FF E0
    BYTE push_ret[6];               // 68 XX XX XX XX C3
} HOOK_PATTERNS;

// Halo's Gate context
typedef struct _HALO_GATE_CTX {
    PVOID ntdll_base;
    PVOID ntdll_clean_copy;         // Clean ntdll for comparison
    SIZE_T ntdll_size;
    HOOK_PATTERNS hook_patterns;
    DWORD resolved_count;
    DWORD failed_count;
    DWORD hooked_count;
} HALO_GATE_CTX, *PHALO_GATE_CTX;

// ========================================================================
// CORE HALO'S GATE FUNCTIONS
// ========================================================================

// Initialize Halo's Gate engine
BOOL HaloGate_Initialize(struct _RTLDR_CTX* ctx, PHALO_GATE_CTX halo_ctx);

// Advanced syscall ID resolution with multiple fallback methods
BOOL HaloGate_ResolveSyscallAdvanced(
    PHALO_GATE_CTX halo_ctx,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
);

// Direct syscall resolution (fastest path)
BOOL HaloGate_ResolveDirect(
    PVOID ntdll_base,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
);

// Halo's Gate: resolve via neighbor functions when target is hooked
BOOL HaloGate_ResolveViaNeighbors(
    PVOID ntdll_base,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
);

// Tartarus Gate: unhook and re-resolve
BOOL TartarusGate_UnhookAndResolve(
    PHALO_GATE_CTX halo_ctx,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
);

// Hell's Gate: manual .text section scanning fallback
BOOL HellGate_ManualScan(
    PVOID ntdll_base,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
);

// ========================================================================
// HOOK DETECTION & ANALYSIS
// ========================================================================

// Detect if function is hooked
BOOL HaloGate_IsHooked(PVOID function_address, PBYTE original_bytes);

// Advanced pattern analysis for hook detection
BOOL HaloGate_AnalyzeHookPattern(PVOID function_address);

// Get neighbor function for Halo's Gate technique
PVOID HaloGate_GetNeighborFunction(PVOID ntdll_base, const char* target_function, INT offset);

// Calculate syscall ID from neighbor function
DWORD HaloGate_CalculateSyscallFromNeighbor(DWORD neighbor_id, INT function_offset);

// ========================================================================
// UTILITY FUNCTIONS
// ========================================================================

// Load clean ntdll copy for comparison
BOOL HaloGate_LoadCleanNtdll(PHALO_GATE_CTX halo_ctx);

// Cleanup Halo's Gate resources
VOID HaloGate_Cleanup(PHALO_GATE_CTX halo_ctx);

// Get function order in export table (for neighbor calculation)
INT HaloGate_GetFunctionOrdinal(PVOID ntdll_base, const char* function_name);

#endif // HALO_GATE_H 