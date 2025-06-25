#ifndef KERNEL_DIRECT_SYSCALLS_H
#define KERNEL_DIRECT_SYSCALLS_H

#include "common_defines.h"

// ========================================================================
// KERNEL DIRECT SYSCALLS v1.0 - "Revolutionary Usermode Hook Bypass"
// "When you bypass usermode so hard, you're practically in kernel space" - Elite
// ========================================================================

// SSDT (System Service Descriptor Table) structures
typedef struct _SYSTEM_SERVICE_TABLE {
    PULONG ServiceTableBase;        // Pointer to syscall function addresses
    PULONG ServiceCounterTableBase; // Optional counter table
    ULONG NumberOfServices;         // Number of services in table
    PUCHAR ParamTableBase;          // Parameter table (argument count)
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

// Simple time structure for our needs
typedef struct _SIMPLE_SYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} SIMPLE_SYSTEM_TIME;

// KUSER_SHARED_DATA structure (partial)
typedef struct _KUSER_SHARED_DATA_PARTIAL {
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    SIMPLE_SYSTEM_TIME InterruptTime;
    SIMPLE_SYSTEM_TIME SystemTime;
    SIMPLE_SYSTEM_TIME TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG AitSamplingValue;
    ULONG AppCompatFlag;
    ULONGLONG RNGSeedVersion;
    ULONG GlobalValidationRunlevel;
    LONG TimeZoneBiasStamp;
    ULONG NtBuildNumber;            // Build number for version checking
    // ... truncated for our needs
} KUSER_SHARED_DATA_PARTIAL, *PKUSER_SHARED_DATA_PARTIAL;

// Kernel direct syscall context
typedef struct _KERNEL_SYSCALL_CONTEXT {
    // Kernel module information
    PVOID ntoskrnl_base;            // ntoskrnl.exe base address
    SIZE_T ntoskrnl_size;           // Size of ntoskrnl.exe
    PVOID hal_base;                 // hal.dll base address (if needed)
    
    // SSDT information
    PSYSTEM_SERVICE_TABLE ssdt;     // Main SSDT
    PSYSTEM_SERVICE_TABLE shadow_ssdt; // Shadow SSDT (GUI syscalls)
    PULONG syscall_table;           // Resolved syscall table
    ULONG syscall_count;            // Number of syscalls
    
    // Version and compatibility
    DWORD windows_version;          // Windows version
    DWORD build_number;             // Build number
    BOOL is_wow64;                  // WoW64 environment?
    BOOL ssdt_resolved;             // SSDT successfully resolved?
    
    // Performance and caching
    ULONG resolved_syscalls;        // Number of resolved syscalls
    LARGE_INTEGER resolution_time;  // Time taken to resolve SSDT
    BOOL use_cache;                 // Use syscall ID cache?
    
    // Security and stealth
    BOOL anti_hook_mode;            // Anti-hook mode enabled?
    BOOL stealth_mode;              // Extra stealth measures?
    DWORD access_method;            // Method used to access kernel
} KERNEL_SYSCALL_CONTEXT, *PKERNEL_SYSCALL_CONTEXT;

// Syscall resolution methods
typedef enum _KERNEL_ACCESS_METHOD {
    KERNEL_ACCESS_KUSER_SHARED = 1,     // Via KUSER_SHARED_DATA
    KERNEL_ACCESS_NTDLL_PARSE = 2,      // Parse from ntdll exports
    KERNEL_ACCESS_DIRECT_READ = 3,      // Direct kernel memory read
    KERNEL_ACCESS_PATTERN_SCAN = 4,     // Pattern scanning
    KERNEL_ACCESS_REGISTRY = 5,         // Registry-based resolution
    KERNEL_ACCESS_WOW64_GATE = 6,       // WoW64 Heaven's Gate
} KERNEL_ACCESS_METHOD;

// Syscall execution methods
typedef enum _SYSCALL_EXECUTION_METHOD {
    EXEC_METHOD_DIRECT = 1,             // Direct syscall instruction
    EXEC_METHOD_SYSENTER = 2,           // SYSENTER instruction (x86)
    EXEC_METHOD_HEAVEN_GATE = 3,        // WoW64 transition
    EXEC_METHOD_INDIRECT = 4,           // Indirect through ntdll
    EXEC_METHOD_MANUAL_GATE = 5,        // Manual gate construction
} SYSCALL_EXECUTION_METHOD;

// Kernel syscall descriptor
typedef struct _KERNEL_SYSCALL_DESCRIPTOR {
    LPCSTR function_name;           // Function name (e.g., "NtCreateFile")
    DWORD syscall_id;               // Resolved syscall ID
    PVOID kernel_address;           // Address in kernel
    PVOID usermode_address;         // Address in ntdll (for comparison)
    BOOL is_hooked;                 // Is usermode function hooked?
    BOOL is_resolved;               // Successfully resolved?
    SYSCALL_EXECUTION_METHOD exec_method; // Preferred execution method
    ULONG parameter_count;          // Number of parameters
    LARGE_INTEGER last_used;        // Last usage timestamp
} KERNEL_SYSCALL_DESCRIPTOR, *PKERNEL_SYSCALL_DESCRIPTOR;

// Global kernel syscall context
extern KERNEL_SYSCALL_CONTEXT g_kernel_ctx;

// ========================================================================
// REVOLUTIONARY API - "Bypass usermode like a boss"
// ========================================================================

// Initialize kernel direct syscalls system
BOOL KernelSyscalls_Initialize(VOID);

// Resolve ntoskrnl.exe base address
PVOID KernelSyscalls_ResolveNtoskrnlBase(KERNEL_ACCESS_METHOD method);

// Parse and resolve SSDT from kernel
NTSTATUS KernelSyscalls_ResolveSSdt(PVOID ntoskrnl_base);

// Resolve specific syscall ID from kernel
DWORD KernelSyscalls_ResolveSyscallId(LPCSTR function_name);

// Execute syscall using kernel-direct method
NTSTATUS KernelSyscalls_Execute(
    DWORD syscall_id,
    SYSCALL_EXECUTION_METHOD method,
    ULONG parameter_count,
    ...
);

// Cleanup kernel syscalls system
VOID KernelSyscalls_Cleanup(VOID);

// ========================================================================
// KERNEL RESOLUTION METHODS - "Multiple paths to kernel enlightenment"
// ========================================================================

// Method 1: KUSER_SHARED_DATA approach
PVOID KernelSyscalls_ResolveViaKUserShared(VOID);

// Method 2: Parse from ntdll exports and calculate offset
PVOID KernelSyscalls_ResolveViaNtdllParsing(VOID);

// Method 3: Direct kernel memory reading (advanced)
PVOID KernelSyscalls_ResolveViaDirectRead(VOID);

// Method 4: Pattern scanning in kernel space
PVOID KernelSyscalls_ResolveViaPatternScan(VOID);

// Method 5: Registry-based resolution
PVOID KernelSyscalls_ResolveViaRegistry(VOID);

// ========================================================================
// SSDT PARSING AND ANALYSIS - "Kernel table archaeology"
// ========================================================================

// Parse SSDT from ntoskrnl.exe
NTSTATUS KernelSyscalls_ParseSSdt(
    PVOID ntoskrnl_base,
    PSYSTEM_SERVICE_TABLE* ssdt,
    PULONG* syscall_table,
    PULONG syscall_count
);

// Find SSDT in kernel image
PVOID KernelSyscalls_FindSsdtInKernel(PVOID ntoskrnl_base, SIZE_T kernel_size);

// Validate SSDT structure
BOOL KernelSyscalls_ValidateSSdt(PSYSTEM_SERVICE_TABLE ssdt);

// Parse individual syscall from SSDT
NTSTATUS KernelSyscalls_ParseSyscallEntry(
    PSYSTEM_SERVICE_TABLE ssdt,
    DWORD index,
    PVOID* syscall_address,
    PULONG parameter_count
);

// ========================================================================
// SYSCALL EXECUTION ENGINE - "The kernel caller"
// ========================================================================

// Direct syscall execution (x64)
NTSTATUS KernelSyscalls_ExecuteDirect(
    DWORD syscall_id,
    ULONG parameter_count,
    PVOID parameters
);

// SYSENTER execution (x86)
NTSTATUS KernelSyscalls_ExecuteSysenter(
    DWORD syscall_id,
    ULONG parameter_count,
    PVOID parameters
);

// Heaven's Gate execution (WoW64)
NTSTATUS KernelSyscalls_ExecuteHeavenGate(
    DWORD syscall_id,
    ULONG parameter_count,
    PVOID parameters
);

// Manual gate construction and execution
NTSTATUS KernelSyscalls_ExecuteManualGate(
    DWORD syscall_id,
    ULONG parameter_count,
    PVOID parameters
);

// ========================================================================
// ANTI-HOOK AND STEALTH FEATURES - "Invisible kernel access"
// ========================================================================

// Detect usermode hooks by comparing with kernel
BOOL KernelSyscalls_DetectUserModeHooks(LPCSTR function_name);

// Compare usermode vs kernel function bytes
BOOL KernelSyscalls_CompareFunctionBytes(
    PVOID usermode_addr,
    PVOID kernel_addr,
    SIZE_T compare_size
);

// Enable stealth mode (extra anti-detection measures)
VOID KernelSyscalls_EnableStealthMode(BOOL enable);

// Randomize syscall execution timing
VOID KernelSyscalls_RandomizeExecution(VOID);

// Obfuscate kernel access patterns
VOID KernelSyscalls_ObfuscateAccess(VOID);

// ========================================================================
// UTILITY AND HELPER FUNCTIONS - "The supporting arsenal"
// ========================================================================

// Get Windows version for compatibility
DWORD KernelSyscalls_GetWindowsVersion(VOID);

// Check WoW64 environment
BOOL KernelSyscalls_IsWoW64(VOID);

// Validate kernel address
BOOL KernelSyscalls_IsValidKernelAddress(PVOID address);

// Calculate RVA from kernel base
PVOID KernelSyscalls_RvaToVa(PVOID base, DWORD rva);

// Find export in kernel module
PVOID KernelSyscalls_FindKernelExport(PVOID kernel_base, LPCSTR export_name);

// ========================================================================
// PERFORMANCE AND CACHING - "Speed meets stealth"
// ========================================================================

// Cache resolved syscall IDs
VOID KernelSyscalls_CacheSyscallId(LPCSTR function_name, DWORD syscall_id);

// Lookup cached syscall ID
DWORD KernelSyscalls_LookupCachedSyscallId(LPCSTR function_name);

// Preload commonly used syscalls
NTSTATUS KernelSyscalls_PreloadCommonSyscalls(VOID);

// Benchmark syscall execution methods
VOID KernelSyscalls_BenchmarkMethods(VOID);

// ========================================================================
// LOGGING AND DIAGNOSTICS - "Document the kernel magic"
// ========================================================================

// Log kernel resolution attempt
VOID KernelSyscalls_LogResolutionAttempt(KERNEL_ACCESS_METHOD method, NTSTATUS result);

// Log SSDT parsing results
VOID KernelSyscalls_LogSsdtParsing(PSYSTEM_SERVICE_TABLE ssdt, ULONG syscall_count);

// Log syscall execution
VOID KernelSyscalls_LogSyscallExecution(
    LPCSTR function_name,
    DWORD syscall_id,
    SYSCALL_EXECUTION_METHOD method,
    NTSTATUS result
);

// Generate kernel access report
VOID KernelSyscalls_GenerateReport(VOID);

// ========================================================================
// ADVANCED KERNEL TECHNIQUES - "Next level kernel mastery"
// ========================================================================

// Shadow SSDT access (GUI syscalls)
NTSTATUS KernelSyscalls_AccessShadowSSdt(VOID);

// Kernel callback enumeration and analysis
NTSTATUS KernelSyscalls_EnumerateKernelCallbacks(VOID);

// KPCR (Kernel Processor Control Region) access
PVOID KernelSyscalls_GetKpcr(VOID);

// IDT (Interrupt Descriptor Table) analysis
NTSTATUS KernelSyscalls_AnalyzeIdt(VOID);

// ========================================================================
// COMPATIBILITY AND FALLBACK - "Always have a backup plan"
// ========================================================================

// Fallback to traditional syscalls if kernel method fails
NTSTATUS KernelSyscalls_FallbackToTraditional(
    LPCSTR function_name,
    ULONG parameter_count,
    PVOID parameters
);

// Check method compatibility with current system
BOOL KernelSyscalls_IsMethodCompatible(KERNEL_ACCESS_METHOD method);

// Auto-select best method for current environment
KERNEL_ACCESS_METHOD KernelSyscalls_SelectOptimalMethod(VOID);

// Graceful degradation if kernel access fails
VOID KernelSyscalls_GracefulDegradation(VOID);

#endif // KERNEL_DIRECT_SYSCALLS_H 