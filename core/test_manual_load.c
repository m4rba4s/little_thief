#include "../include/common_defines.h"
#include "../include/rtldr_ctx.h"
#include "../include/strategy.h"
#include "../include/manual_loader.h"
#include "../include/syscalls.h"
#include "../include/mem.h"

// Test function to demonstrate the manual loading framework
BOOL TestManualLoadFramework(PRTLDR_CTX ctx) {
    EVASION_STRATEGY strategy = {0};
    NTSTATUS status;
    
    if (!ctx) {
        return FALSE;
    }
    
    // Test 1: Load Ekko strategy (baseline)
    if (!Strategy_LoadByType(ctx, &strategy, STRATEGY_EKKO)) {
        return FALSE;
    }
    
    // Test Ekko sleep obfuscation
    if (strategy.pfnObfuscateSleep) {
        strategy.pfnObfuscateSleep(ctx, 1000); // 1 second sleep with obfuscation
    }
    
    // Cleanup Ekko
    if (strategy.pfnCleanup) {
        strategy.pfnCleanup(ctx);
    }
    
    // Reset strategy
    for (SIZE_T i = 0; i < sizeof(EVASION_STRATEGY); i++) {
        ((BYTE*)&strategy)[i] = 0;
    }
    
    // Test 2: Load Manual Loading strategy
    if (!Strategy_LoadByType(ctx, &strategy, STRATEGY_MANUAL_LOAD)) {
        return FALSE;
    }
    
    // Test manual loading capabilities
    // Note: In real scenario, you would load actual DLL data
    // For now, we just test the framework initialization
    
    // Cleanup Manual Load
    if (strategy.pfnCleanup) {
        strategy.pfnCleanup(ctx);
    }
    
    // Reset strategy
    for (SIZE_T i = 0; i < sizeof(EVASION_STRATEGY); i++) {
        ((BYTE*)&strategy)[i] = 0;
    }
    
    // Test 3: Load Combined strategy (Ekko + Manual Load)
    if (!Strategy_LoadByType(ctx, &strategy, STRATEGY_COMBINED)) {
        return FALSE;
    }
    
    // Test combined capabilities
    if (strategy.pfnObfuscateSleep) {
        strategy.pfnObfuscateSleep(ctx, 500); // 0.5 second sleep
    }
    
    // Cleanup Combined
    if (strategy.pfnCleanup) {
        strategy.pfnCleanup(ctx);
    }
    
    return TRUE;
}

// Enhanced loader entry point with manual loading demonstration
BOOL DemoManualLoadingCapabilities(PRTLDR_CTX ctx) {
    if (!ctx) {
        return FALSE;
    }
    
    // Set up memory management functions (using simple heap)
    ctx->mem_alloc = HeapAlloc;
    ctx->mem_free = HeapFree;
    
    // Run manual loading framework tests
    if (!TestManualLoadFramework(ctx)) {
        return FALSE;
    }
    
    return TRUE;
}

// Report framework capabilities
VOID ReportFrameworkCapabilities(VOID) {
    // In a real implementation, this could output to a log or callback
    // For now, it's just a placeholder demonstrating the available features
    
    // Available strategies:
    // 1. STRATEGY_EKKO - Sleep obfuscation with XOR encryption
    // 2. STRATEGY_MANUAL_LOAD - Manual DLL loading with stealth features
    // 3. STRATEGY_COMBINED - Combined Ekko + Manual Loading
    
    // Available features:
    // - Unbacked memory allocation (bypass PsSetLoadImageNotifyRoutine)
    // - Manual PE parsing and loading
    // - Position independent code execution
    // - Modular strategy framework
    // - Sleep obfuscation techniques
    // - XOR encryption for memory protection
} 