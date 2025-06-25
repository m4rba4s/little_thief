#include "../include/common_defines.h"
#include "../include/rtldr_ctx.h"
#include "../include/syscalls.h"

#pragma warning(push)

// Forward declaration of the core loader function
extern int CoreLoaderMain(void);

// Custom entry point function
void RealEntry(void) {
    int exitCode = 1; // Default exit code in case CoreLoaderMain crashes early

    // Call the main logic of the loader
    exitCode = CoreLoaderMain();

    // Add a pause to see results (for debugging)
    #ifdef _DEBUG
    MessageBoxA(NULL, "PhantomEdge completed. Press OK to exit.", "PhantomEdge Debug", MB_OK);
    #else
    // Even in Release, let's add a small message for testing
    MessageBoxA(NULL, "PhantomEdge execution completed!", "PhantomEdge", MB_OK);
    #endif

    // Terminate the process using the syscall wrapper
    // Use NtCurrentProcess() macro for the current process handle
    // Pass the exit code obtained from CoreLoaderMain
    wrapped_NtTerminateProcess(NtCurrentProcess(), (NTSTATUS)exitCode);

    // Should not reach here if NtTerminateProcess succeeds
    // Add infinite loop or similar just in case
    for(;;);
}

/* Commented out old main function
int main(void) {
    MessageBoxA(NULL, "Stub Entry Point Reached!", "Phantom Edge Stub", MB_OK);
    return 0;
}
*/ 