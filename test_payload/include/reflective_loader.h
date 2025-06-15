#ifndef REFLECTIVE_LOADER_H
#define REFLECTIVE_LOADER_H

// #include <windows.h> // Replaced by common_defines.h from root include path
// #include <winnt.h>   // Replaced by common_defines.h
// Assuming common_defines.h provides necessary types like LPVOID, WINAPI
// The build system needs to be configured to find "common_defines.h"
// For example, target_include_directories(test_payload PRIVATE ${CMAKE_SOURCE_DIR}/include)
#include "../../include/common_defines.h" // Path relative to this file


// Function pointer type for the ReflectiveLoader
// It takes an LPVOID (typically unused by simple reflective loaders, but part of sRDI spec)
// and returns LPVOID (the base address of the loaded module, or NULL on failure).
typedef LPVOID (WINAPI *pReflectiveLoader_t)(LPVOID lpParameter);

// Define the ReflectiveLoader export
#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) LPVOID WINAPI ReflectiveLoader(LPVOID lpParameter);

#ifdef __cplusplus
}
#endif

// We might need helper function declarations here later

#endif // REFLECTIVE_LOADER_H 