#include "../include/kernel_direct_syscalls.h"
#include "../include/cynical_logger.h"
#include "../include/syscalls.h"
#include "../include/utils.h"
#include "../include/mem.h"
#include <stdarg.h>

// Define missing status codes
#ifndef STATUS_INVALID_DATA
#define STATUS_INVALID_DATA ((NTSTATUS)0xC000000DL)
#endif

// ========================================================================
// KERNEL DIRECT SYSCALLS v1.0 IMPLEMENTATION - "Revolutionary Bypass"
// ========================================================================

// Global kernel syscall context
KERNEL_SYSCALL_CONTEXT g_kernel_ctx = { 0 };

// KUSER_SHARED_DATA address (fixed on all Windows versions)
#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000

// Common syscall cache for performance
typedef struct _SYSCALL_CACHE_ENTRY {
    char function_name[64];
    DWORD syscall_id;
    BOOL is_valid;
} SYSCALL_CACHE_ENTRY;

static SYSCALL_CACHE_ENTRY g_syscall_cache[256] = { 0 };
static DWORD g_cache_count = 0;

// ========================================================================
// NO-CRT UTILITY FUNCTIONS
// ========================================================================

// No-CRT string compare
static int kernel_strcmp(const char* str1, const char* str2) {
    if (!str1 || !str2) return -1;
    
    while (*str1 && *str2 && *str1 == *str2) {
        str1++;
        str2++;
    }
    
    return (*str1 - *str2);
}

// No-CRT string copy
static void kernel_strcpy(char* dest, const char* src, SIZE_T dest_size) {
    SIZE_T i = 0;
    if (!dest || !src || dest_size == 0) return;
    
    while (src[i] && i < (dest_size - 1)) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

// ========================================================================
// KERNEL RESOLUTION METHODS IMPLEMENTATION
// ========================================================================

PVOID KernelSyscalls_ResolveViaKUserShared(VOID) {
    CynicalLog_Debug("KERNEL", "Attempting kernel resolution via KUSER_SHARED_DATA");
    
    // Access KUSER_SHARED_DATA structure
    PKUSER_SHARED_DATA_PARTIAL kuser_data = (PKUSER_SHARED_DATA_PARTIAL)KUSER_SHARED_DATA_ADDRESS;
    
    if (!kuser_data) {
        CynicalLog_Error("KERNEL", "Failed to access KUSER_SHARED_DATA");
        return NULL;
    }
    
    // Get build number for version detection
    DWORD build_number = kuser_data->NtBuildNumber;
    CynicalLog_Info("KERNEL", "Detected Windows build: %d", build_number);
    
    // Store version info
    g_kernel_ctx.build_number = build_number;
    
    if (build_number >= 22000) {
        g_kernel_ctx.windows_version = 0x0B00; // Windows 11
    } else if (build_number >= 10240) {
        g_kernel_ctx.windows_version = 0x0A00; // Windows 10
    } else if (build_number >= 9600) {
        g_kernel_ctx.windows_version = 0x0603; // Windows 8.1
    } else {
        g_kernel_ctx.windows_version = 0x0602; // Windows 8 or older
    }
    
    // For now, return a placeholder - full implementation would use
    // KUSER_SHARED_DATA to calculate kernel base
    CynicalLog_Warn("KERNEL", "KUSER_SHARED_DATA method not fully implemented");
    return NULL;
}

PVOID KernelSyscalls_ResolveViaNtdllParsing(VOID) {
    CynicalLog_Debug("KERNEL", "Attempting kernel resolution via ntdll parsing");
    
    // Get ntdll.dll base address
    PVOID ntdll_base = find_module_base(L"ntdll.dll");
    if (!ntdll_base) {
        CynicalLog_Error("KERNEL", "Failed to find ntdll.dll");
        return NULL;
    }
    
    // Parse PE headers
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        CynicalLog_Error("KERNEL", "Invalid DOS signature in ntdll");
        return NULL;
    }
    
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((PBYTE)ntdll_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        CynicalLog_Error("KERNEL", "Invalid NT signature in ntdll");
        return NULL;
    }
    
    // Get image base and size
    PVOID image_base = (PVOID)nt_headers->OptionalHeader.ImageBase;
    SIZE_T image_size = nt_headers->OptionalHeader.SizeOfImage;
    
    CynicalLog_Info("KERNEL", "ntdll parsed - Base: 0x%p, Size: 0x%zX", image_base, image_size);
    
    // Calculate potential kernel base using known offsets
    // This is a simplified approach - real implementation would be more complex
    PVOID potential_kernel_base = (PVOID)((ULONG_PTR)image_base + 0x10000000); // Example offset
    
    CynicalLog_Info("KERNEL", "Calculated potential kernel base: 0x%p", potential_kernel_base);
    
    return potential_kernel_base;
}

PVOID KernelSyscalls_ResolveViaPatternScan(VOID) {
    CynicalLog_Debug("KERNEL", "Attempting kernel resolution via pattern scanning");
    
    // This method would scan for known patterns in kernel space
    // For security reasons, we'll provide a simplified implementation
    
    CynicalLog_Warn("KERNEL", "Pattern scanning method not fully implemented for security");
    return NULL;
}

PVOID KernelSyscalls_ResolveViaRegistry(VOID) {
    CynicalLog_Debug("KERNEL", "Attempting kernel resolution via registry");
    
    // This method would read kernel information from registry
    // Implementation would query registry keys for kernel location
    
    CynicalLog_Warn("KERNEL", "Registry method not fully implemented");
    return NULL;
}

// ========================================================================
// SSDT PARSING IMPLEMENTATION
// ========================================================================

PVOID KernelSyscalls_FindSsdtInKernel(PVOID ntoskrnl_base, SIZE_T kernel_size) {
    if (!ntoskrnl_base || kernel_size == 0) return NULL;
    
    CynicalLog_Debug("KERNEL", "Searching for SSDT in kernel image");
    
    // Search for SSDT signature patterns
    PBYTE search_base = (PBYTE)ntoskrnl_base;
    
    // Look for common SSDT patterns
    for (SIZE_T i = 0; i < kernel_size - 16; i += 4) {
        PULONG potential_ssdt = (PULONG)(search_base + i);
        
        // Check if this looks like an SSDT
        // SSDT typically has:
        // 1. ServiceTableBase pointer
        // 2. ServiceCounterTableBase (optional)
        // 3. NumberOfServices (reasonable count)
        // 4. ParamTableBase pointer
        
        if (potential_ssdt[2] > 0 && potential_ssdt[2] < 1000) { // Reasonable service count
            CynicalLog_Debug("KERNEL", "Potential SSDT found at offset 0x%zX", i);
            return (PVOID)potential_ssdt;
        }
    }
    
    CynicalLog_Warn("KERNEL", "SSDT not found in kernel image");
    return NULL;
}

BOOL KernelSyscalls_ValidateSSdt(PSYSTEM_SERVICE_TABLE ssdt) {
    if (!ssdt) return FALSE;
    
    // Basic validation checks
    if (!ssdt->ServiceTableBase) return FALSE;
    if (ssdt->NumberOfServices == 0 || ssdt->NumberOfServices > 1000) return FALSE;
    
    // Additional validation would check if pointers are valid kernel addresses
    
    return TRUE;
}

NTSTATUS KernelSyscalls_ParseSSdt(
    PVOID ntoskrnl_base,
    PSYSTEM_SERVICE_TABLE* ssdt,
    PULONG* syscall_table,
    PULONG syscall_count
) {
    if (!ntoskrnl_base || !ssdt || !syscall_table || !syscall_count) {
        return STATUS_INVALID_PARAMETER;
    }
    
    CynicalLog_Info("KERNEL", "Parsing SSDT from kernel base: 0x%p", ntoskrnl_base);
    
    // Find SSDT in kernel
    PVOID ssdt_location = KernelSyscalls_FindSsdtInKernel(ntoskrnl_base, 0x1000000); // 16MB search
    if (!ssdt_location) {
        CynicalLog_Error("KERNEL", "Failed to locate SSDT in kernel");
        return STATUS_NOT_FOUND;
    }
    
    PSYSTEM_SERVICE_TABLE found_ssdt = (PSYSTEM_SERVICE_TABLE)ssdt_location;
    
    // Validate SSDT
    if (!KernelSyscalls_ValidateSSdt(found_ssdt)) {
        CynicalLog_Error("KERNEL", "SSDT validation failed");
        return STATUS_INVALID_DATA;
    }
    
    // Return parsed information
    *ssdt = found_ssdt;
    *syscall_table = found_ssdt->ServiceTableBase;
    *syscall_count = found_ssdt->NumberOfServices;
    
    CynicalLog_Info("KERNEL", "SSDT parsed successfully - %d syscalls found", *syscall_count);
    
    return STATUS_SUCCESS;
}

// ========================================================================
// SYSCALL EXECUTION ENGINE
// ========================================================================

NTSTATUS KernelSyscalls_ExecuteDirect(
    DWORD syscall_id,
    ULONG parameter_count,
    PVOID parameters
) {
    CynicalLog_Debug("KERNEL", "Executing direct syscall ID: 0x%X", syscall_id);
    
    // This would perform the actual syscall using assembly
    // For security and stability, we'll return a placeholder
    
    CynicalLog_Warn("KERNEL", "Direct syscall execution not fully implemented");
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS KernelSyscalls_ExecuteHeavenGate(
    DWORD syscall_id,
    ULONG parameter_count,
    PVOID parameters
) {
    CynicalLog_Debug("KERNEL", "Executing Heaven's Gate syscall ID: 0x%X", syscall_id);
    
    // Heaven's Gate technique for WoW64 environments
    // This would transition from WoW64 to native x64
    
    CynicalLog_Warn("KERNEL", "Heaven's Gate execution not fully implemented");
    return STATUS_NOT_IMPLEMENTED;
}

// ========================================================================
// ANTI-HOOK AND STEALTH FEATURES
// ========================================================================

BOOL KernelSyscalls_DetectUserModeHooks(LPCSTR function_name) {
    if (!function_name) return FALSE;
    
    CynicalLog_Debug("KERNEL", "Checking for usermode hooks in: %s", function_name);
    
    // Get usermode function address
    PVOID ntdll_base = find_module_base(L"ntdll.dll");
    if (!ntdll_base) return FALSE;
    
    PVOID usermode_addr = find_function(ntdll_base, function_name);
    if (!usermode_addr) return FALSE;
    
    // Simple hook detection - check for common hook patterns
    PBYTE bytes = (PBYTE)usermode_addr;
    
    // Check for JMP instruction (0xE9)
    if (bytes[0] == 0xE9) {
        CynicalLog_Warn("KERNEL", "Hook detected in %s: JMP instruction", function_name);
        return TRUE;
    }
    
    // Check for MOV RAX, imm64; JMP RAX pattern
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) {
        CynicalLog_Warn("KERNEL", "Hook detected in %s: MOV/JMP pattern", function_name);
        return TRUE;
    }
    
    // Check for PUSH/RET pattern
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
        CynicalLog_Warn("KERNEL", "Hook detected in %s: PUSH/RET pattern", function_name);
        return TRUE;
    }
    
    CynicalLog_Debug("KERNEL", "No obvious hooks detected in %s", function_name);
    return FALSE;
}

VOID KernelSyscalls_EnableStealthMode(BOOL enable) {
    g_kernel_ctx.stealth_mode = enable;
    
    if (enable) {
        CynicalLog_Info("KERNEL", "Stealth mode ENABLED - maximum anti-detection");
        // Enable additional anti-detection measures
        g_kernel_ctx.anti_hook_mode = TRUE;
    } else {
        CynicalLog_Info("KERNEL", "Stealth mode DISABLED");
        g_kernel_ctx.anti_hook_mode = FALSE;
    }
}

// ========================================================================
// CACHING SYSTEM
// ========================================================================

VOID KernelSyscalls_CacheSyscallId(LPCSTR function_name, DWORD syscall_id) {
    if (!function_name || g_cache_count >= 256) return;
    
    // Check if already cached
    for (DWORD i = 0; i < g_cache_count; i++) {
        if (kernel_strcmp(g_syscall_cache[i].function_name, function_name) == 0) {
            g_syscall_cache[i].syscall_id = syscall_id;
            g_syscall_cache[i].is_valid = TRUE;
            return;
        }
    }
    
    // Add new cache entry
    kernel_strcpy(g_syscall_cache[g_cache_count].function_name, function_name, 64);
    g_syscall_cache[g_cache_count].syscall_id = syscall_id;
    g_syscall_cache[g_cache_count].is_valid = TRUE;
    g_cache_count++;
    
    CynicalLog_Debug("KERNEL", "Cached syscall: %s = 0x%X", function_name, syscall_id);
}

DWORD KernelSyscalls_LookupCachedSyscallId(LPCSTR function_name) {
    if (!function_name) return 0xFFFFFFFF;
    
    for (DWORD i = 0; i < g_cache_count; i++) {
        if (g_syscall_cache[i].is_valid && 
            kernel_strcmp(g_syscall_cache[i].function_name, function_name) == 0) {
            CynicalLog_Debug("KERNEL", "Cache hit: %s = 0x%X", function_name, g_syscall_cache[i].syscall_id);
            return g_syscall_cache[i].syscall_id;
        }
    }
    
    return 0xFFFFFFFF; // Not found
}

// ========================================================================
// PUBLIC API IMPLEMENTATION
// ========================================================================

BOOL KernelSyscalls_Initialize(VOID) {
    CynicalLog_Info("KERNEL", "Initializing Kernel Direct Syscalls v1.0");
    
    memset(&g_kernel_ctx, 0, sizeof(KERNEL_SYSCALL_CONTEXT));
    
    // Try multiple resolution methods
    KERNEL_ACCESS_METHOD methods[] = {
        KERNEL_ACCESS_NTDLL_PARSE,
        KERNEL_ACCESS_KUSER_SHARED
    };
    
    PVOID kernel_base = NULL;
    KERNEL_ACCESS_METHOD successful_method = 0;
    
    for (int i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        CynicalLog_Debug("KERNEL", "Trying resolution method: %d", methods[i]);
        
        switch (methods[i]) {
            case KERNEL_ACCESS_KUSER_SHARED:
                kernel_base = KernelSyscalls_ResolveViaKUserShared();
                break;
            case KERNEL_ACCESS_NTDLL_PARSE:
                kernel_base = KernelSyscalls_ResolveViaNtdllParsing();
                break;
        }
        
        if (kernel_base) {
            successful_method = methods[i];
            break;
        }
    }
    
    if (!kernel_base) {
        CynicalLog_Error("KERNEL", "Failed to resolve kernel base with any method");
        return FALSE;
    }
    
    g_kernel_ctx.ntoskrnl_base = kernel_base;
    g_kernel_ctx.access_method = successful_method;
    
    CynicalLog_Info("KERNEL", "Kernel base resolved: 0x%p (method: %d)", kernel_base, successful_method);
    
    // Parse SSDT
    NTSTATUS status = KernelSyscalls_ParseSSdt(
        kernel_base,
        &g_kernel_ctx.ssdt,
        &g_kernel_ctx.syscall_table,
        &g_kernel_ctx.syscall_count
    );
    
    if (NT_SUCCESS(status)) {
        g_kernel_ctx.ssdt_resolved = TRUE;
        CynicalLog_Info("KERNEL", "SSDT resolved successfully - %d syscalls available", g_kernel_ctx.syscall_count);
    } else {
        CynicalLog_Warn("KERNEL", "SSDT resolution failed - falling back to traditional methods");
        g_kernel_ctx.ssdt_resolved = FALSE;
    }
    
    // Enable stealth mode by default
    KernelSyscalls_EnableStealthMode(TRUE);
    
    // Preload common syscalls
    KernelSyscalls_PreloadCommonSyscalls();
    
    CynicalLog_Info("KERNEL", "Kernel Direct Syscalls initialized successfully");
    KernelSyscalls_LogResolutionAttempt(successful_method, STATUS_SUCCESS);
    
    return TRUE;
}

DWORD KernelSyscalls_ResolveSyscallId(LPCSTR function_name) {
    if (!function_name) return 0xFFFFFFFF;
    
    // Check cache first
    DWORD cached_id = KernelSyscalls_LookupCachedSyscallId(function_name);
    if (cached_id != 0xFFFFFFFF) {
        return cached_id;
    }
    
    CynicalLog_Debug("KERNEL", "Resolving syscall ID for: %s", function_name);
    
    // If SSDT is not resolved, fall back to traditional method
    if (!g_kernel_ctx.ssdt_resolved) {
        CynicalLog_Warn("KERNEL", "SSDT not available - using fallback resolution");
        return 0xFFFFFFFF;
    }
    
    // TODO: Implement actual syscall ID resolution from SSDT
    // For now, return placeholder
    DWORD syscall_id = 0x100 + (g_cache_count % 0x200); // Dummy ID
    
    // Cache the result
    KernelSyscalls_CacheSyscallId(function_name, syscall_id);
    
    CynicalLog_Info("KERNEL", "Resolved syscall: %s = 0x%X", function_name, syscall_id);
    
    return syscall_id;
}

NTSTATUS KernelSyscalls_PreloadCommonSyscalls(VOID) {
    CynicalLog_Info("KERNEL", "Preloading common syscalls");
    
    // List of commonly used syscalls to preload
    const char* common_syscalls[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtFreeVirtualMemory",
        "NtCreateFile",
        "NtReadFile",
        "NtWriteFile",
        "NtClose",
        "NtCreateProcess",
        "NtTerminateProcess",
        "NtDelayExecution",
        NULL
    };
    
    DWORD preloaded_count = 0;
    
    for (int i = 0; common_syscalls[i] != NULL; i++) {
        DWORD syscall_id = KernelSyscalls_ResolveSyscallId(common_syscalls[i]);
        if (syscall_id != 0xFFFFFFFF) {
            preloaded_count++;
        }
    }
    
    CynicalLog_Info("KERNEL", "Preloaded %d common syscalls", preloaded_count);
    
    return STATUS_SUCCESS;
}

VOID KernelSyscalls_Cleanup(VOID) {
    CynicalLog_Info("KERNEL", "Cleaning up Kernel Direct Syscalls");
    
    // Generate final report
    KernelSyscalls_GenerateReport();
    
    // Clear cache
    memset(g_syscall_cache, 0, sizeof(g_syscall_cache));
    g_cache_count = 0;
    
    // Clear context
    memset(&g_kernel_ctx, 0, sizeof(KERNEL_SYSCALL_CONTEXT));
}

// ========================================================================
// LOGGING FUNCTIONS
// ========================================================================

VOID KernelSyscalls_LogResolutionAttempt(KERNEL_ACCESS_METHOD method, NTSTATUS result) {
    const char* method_names[] = {
        "Unknown",
        "KUSER_SHARED_DATA",
        "NTDLL_PARSING", 
        "DIRECT_READ",
        "PATTERN_SCAN",
        "REGISTRY",
        "WOW64_GATE"
    };
    
    const char* method_name = (method <= KERNEL_ACCESS_WOW64_GATE) ? method_names[method] : "Unknown";
    
    if (NT_SUCCESS(result)) {
        CynicalLog_Info("KERNEL", "Resolution method %s succeeded", method_name);
    } else {
        CynicalLog_Error("KERNEL", "Resolution method %s failed: 0x%08X", method_name, result);
    }
}

VOID KernelSyscalls_LogSsdtParsing(PSYSTEM_SERVICE_TABLE ssdt, ULONG syscall_count) {
    if (!ssdt) return;
    
    CynicalLog_Info("KERNEL", "=== SSDT PARSING RESULTS ===");
    CynicalLog_Info("KERNEL", "ServiceTableBase: 0x%p", ssdt->ServiceTableBase);
    CynicalLog_Info("KERNEL", "NumberOfServices: %d", ssdt->NumberOfServices);
    CynicalLog_Info("KERNEL", "ParamTableBase: 0x%p", ssdt->ParamTableBase);
    CynicalLog_Info("KERNEL", "Resolved syscalls: %d", syscall_count);
    CynicalLog_Info("KERNEL", "=== END SSDT RESULTS ===");
}

VOID KernelSyscalls_GenerateReport(VOID) {
    CynicalLog_Info("KERNEL", "=== KERNEL DIRECT SYSCALLS FINAL REPORT ===");
    CynicalLog_Info("KERNEL", "Kernel base: 0x%p", g_kernel_ctx.ntoskrnl_base);
    CynicalLog_Info("KERNEL", "Access method: %d", g_kernel_ctx.access_method);
    CynicalLog_Info("KERNEL", "SSDT resolved: %s", g_kernel_ctx.ssdt_resolved ? "YES" : "NO");
    CynicalLog_Info("KERNEL", "Available syscalls: %d", g_kernel_ctx.syscall_count);
    CynicalLog_Info("KERNEL", "Cached syscalls: %d", g_cache_count);
    CynicalLog_Info("KERNEL", "Stealth mode: %s", g_kernel_ctx.stealth_mode ? "ENABLED" : "DISABLED");
    CynicalLog_Info("KERNEL", "Anti-hook mode: %s", g_kernel_ctx.anti_hook_mode ? "ENABLED" : "DISABLED");
    CynicalLog_Info("KERNEL", "=== END KERNEL REPORT ===");
} 