#include "include/fuzzer.h"
#include <time.h>

void PrintBanner() {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════╗\n");
    printf("║        PHANTOM EDGE PE FUZZER v1.0                ║\n");
    printf("║        Red Team Loader Security Tester            ║\n");
    printf("╚═══════════════════════════════════════════════════╝\n");
    printf("\n");
}

void PrintUsage(const char* program_name) {
    printf("Usage: %s <loader.exe> <target.dll> [options]\n", program_name);
    printf("\nOptions:\n");
    printf("  -i <num>    Number of iterations (default: 1000)\n");
    printf("  -s <strat>  Fuzzing strategy:\n");
    printf("              0 = Random bytes\n");
    printf("              1 = PE-aware mutations\n");
    printf("              2 = Section corruption\n");
    printf("              3 = Import table corruption\n");
    printf("              4 = Export table corruption\n");
    printf("              5 = Header corruption\n");
    printf("  -o <dir>    Output directory for crash samples\n");
    printf("  -t <ms>     Timeout per test in milliseconds (default: 5000)\n");
    printf("  -v          Verbose output\n");
    printf("\nExample:\n");
    printf("  %s PhantomEdge.exe test_payload.dll -i 10000 -s 1\n", program_name);
}

int main(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc < 3) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    // Parse arguments
    LPCSTR loader_path = argv[1];
    LPCSTR target_dll = argv[2];
    DWORD iterations = 1000;
    FUZZ_STRATEGY strategy = FUZZ_PE_AWARE;
    BOOL verbose = FALSE;
    DWORD timeout_ms = 5000;
    LPCSTR output_dir = "crashes";
    
    // Parse optional arguments
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            iterations = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            strategy = (FUZZ_STRATEGY)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = TRUE;
        }
    }
    
    // Seed random number generator
    srand((unsigned int)time(NULL));
    
    // Create output directory
    CreateDirectoryA(output_dir, NULL);
    
    // Initialize fuzzing context
    FUZZ_CONTEXT ctx = {0};
    ctx.strategy = strategy;
    
    printf("[*] Loading target PE: %s\n", target_dll);
    if (!InitializeFuzzer(&ctx, target_dll)) {
        printf("[-] Failed to initialize fuzzer with target PE\n");
        return 1;
    }
    
    printf("[*] Target loader: %s\n", loader_path);
    printf("[*] Fuzzing strategy: %d\n", strategy);
    printf("[*] Iterations: %d\n", iterations);
    printf("[*] Output directory: %s\n", output_dir);
    printf("[*] Timeout: %d ms\n", timeout_ms);
    
    // Setup crash handler
    if (!SetupCrashHandler()) {
        printf("[-] Failed to setup crash handler\n");
        CleanupFuzzer(&ctx);
        return 1;
    }
    
    // Run fuzzing campaign
    printf("\n[*] Starting fuzzing campaign...\n");
    printf("==================================================\n");
    
    RunFuzzingCampaign(&ctx, loader_path, iterations);
    
    // Print results
    printf("\n==================================================\n");
    printf("[+] Fuzzing campaign completed!\n");
    printf("[+] Total mutations: %d\n", ctx.mutation_count);
    printf("[+] Crashes found: %d\n", ctx.crash_count);
    printf("[+] Crash rate: %.2f%%\n", 
           (ctx.crash_count * 100.0) / ctx.mutation_count);
    
    // Cleanup
    CleanupFuzzer(&ctx);
    
    return 0;
} 