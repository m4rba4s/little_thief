# Phantom Edge Loader - Project Log & Task Delegation

**Project Goal:** Create a modular, stealthy, diskless loader for Windows 10/11 (23H2+) capable of bypassing modern EDRs (Defender ATP, CrowdStrike, Cortex) using advanced evasion techniques (Unhooking, Indirect Syscalls, AMSI/ETW Bypass, RDI). See `rules.mdc` for full principles.

**Core Principles:** OPSEC, Modularity, Reliability, Evasion, No-CRT, Minimal Footprint.

---

## Instructions for AI Assistants Delegated Tasks From This Log:

*   **Strict Adherence:** Follow the specified task description, constraints, and context **exactly**. Do not add features or deviate unless explicitly instructed.
*   **Code Style:** Maintain the existing C/ASM style (K&R braces, snake_case, clear comments for non-trivial logic). Code must be compatible with MSVC and potentially GCC/Clang. Assume x64 architecture unless specified otherwise.
*   **No WinAPI (Unless Wrapped):** Do **not** use direct WinAPI calls (e.g., `GetProcAddress`, `LoadLibrary`, `CreateFileW`). Use only the provided wrapper functions (`find_module_base`, `find_function`, `wrapped_Nt*` syscalls) or implement new functionalities using direct PEB/TEB access and syscall wrappers.
*   **Error Handling:** Implement basic error checking (e.g., check return values from syscalls, handle NULL pointers) and return appropriate status codes (NTSTATUS where applicable, or BOOL). Minimize debug prints (`#ifdef _DEBUG`).
*   **OPSEC:** Avoid including unnecessary strings or artifacts that could be signatured. Use custom functions (`memcpy_custom`, `strcmp`, etc.) provided in the codebase instead of CRT functions.
*   **Context:** Refer to the existing codebase (`core/`, `include/`, `stub/`, `CMakeLists.txt`) for context and available functions. Files mentioned in the log should be considered the source of truth for the current state.
*   **Output:** Provide complete, compilable code snippets as requested by the task (usually via `edit_file` tool). Explain *briefly* what was done.

---

## Completed Tasks (Summary):

1.  **Project Setup:** Basic directory structure, `CMakeLists.txt` initialized.
2.  **Core Utilities (PEB/EAT):** Implemented `find_module_base` (PEB Ldr traversal) and `find_function` (EAT parsing) without direct WinAPI calls (`core/utils.c`).
3.  **Indirect Syscalls (Core):**
    *   Implemented ASM stub (`syscall_stub.asm`) for x64 `syscall` instruction.
    *   Implemented dynamic syscall ID resolution (`resolve_syscall_id` in `core/syscalls.c`) using "Relative Syscall Search" (scan forward for `syscall`, backward for `mov eax, id`).
    *   Implemented `__declspec(naked)` wrappers (`wrapped_Nt*`) for key NT functions (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`, `NtCreateFile`, `NtReadFile`, `NtQueryInformationFile`, `NtClose`) using cached IDs and calling the ASM stub (`core/syscalls.c`).
4.  **Memory Management Wrappers:** `alloc_memory`, `protect_memory`, `free_memory` in `core/mem.c` now utilize the `wrapped_Nt*` syscall wrappers.
5.  **Evasion Techniques (Core):**
    *   `unhook_ntdll` (`core/evasion.c`): Refactored to use syscall wrappers (`wrapped_NtCreateFile`, `wrapped_NtQueryInformationFile`, `wrapped_NtReadFile`, `wrapped_NtClose`) for file operations and `alloc/protect/free_memory` wrappers. Still uses `GetSystemDirectoryW` temporarily.
    *   `patch_monitoring_functions` (`core/evasion.c`): Uses `find_module_base`, `find_function`, and `protect_memory` wrapper (indirectly using syscalls).
6.  **Reflective DLL Injection (RDI):** Implemented standard RDI logic (`execute_reflective_dll` in `core/rdi.c`) parsing PE headers from buffer and calling exported `ReflectiveLoader`.
7.  **Core Orchestration:** `CoreLoaderMain` (`core/loader.c`) created to initialize subsystems, run evasion techniques, and execute RDI. Contains placeholder payload.
8.  **Build System:** `CMakeLists.txt` configured to build the executable, including ASM file and Release optimization/stripping flags (but no-CRT linkage not yet enabled).
9.  **Syscall ID Resolution Impr.:** Replaced fixed pattern matching with "Relative Syscall Search" in `resolve_syscall_id` (`core/syscalls.c`).
10. **No-CRT Implementation (Core):**
    *   Removed `printf` calls and `stdio.h` includes.
    *   Added syscall wrapper for `NtTerminateProcess` (`core/syscalls.c`, `include/syscalls.h`).
    *   Implemented custom entry point `RealEntry` in `stub/entry.c` calling `CoreLoaderMain` and `wrapped_NtTerminateProcess`.
    *   Configured CMake for Release builds with `/NODEFAULTLIB`, `/ENTRY:RealEntry`, `/SUBSYSTEM:WINDOWS`, `/GS-` (MSVC). Debug builds retain CRT for now.

---

## Current Task: REVIEW & TESTING PREPARATION

**Goal:** Review the current state after No-CRT implementation and prepare for initial testing.

**Checklist:**
*   [ ] **(Task 1)** Code Review: Perform final review pass (Mode 5).
*   [ ] **(Task 2)** Prepare Test Payload: Create/obtain a simple Reflective DLL (e.g., MessageBox).
*   [ ] **(Task 3)** Embed Payload: Convert DLL to C array and replace placeholder in `core/loader.c`.
*   [ ] **(Task 4)** Finalize Build Config (Task F3): Resolve any remaining linker issues for Release No-CRT build.
*   [ ] **(Task 5)** Initial Test Run: Compile and execute on target system, check functionality and basic EDR bypass.

---

## Future Plans / Potential Tasks for Delegation:

*   **(Task F1: Syscall ID Robustness)** Replace "Relative Syscall Search" in `resolve_syscall_id` with a full Halo's Gate / Tartarus Gate implementation (finding IDs relative to multiple known exported function addresses).
    *   *Constraint:* Must use existing `find_function`. Must update `resolve_syscall_id` in `core/syscalls.c`.
*   **(Task F2: Get System Directory (PEB))** Replace temporary `GetSystemDirectoryW` call in `get_system_dir_peb` (`core/evasion.c`) with proper parsing of PEB -> ProcessParameters -> SystemDirectory `UNICODE_STRING`.
    *   *Constraint:* Requires defining `RTL_USER_PROCESS_PARAMETERS` structure (simplified) or accessing fields via careful offset calculations. Update `get_system_dir_peb`.
*   **(Task F3: Finalize No-CRT Build)** Resolve any linker errors from enabling `/NODEFAULTLIB`. Ensure necessary compiler intrinsics or minimal libs are linked if required by compiler/platform, while minimizing external dependencies. Consider `/GS-` flag. Update `CMakeLists.txt`.
*   **(Task F4: Sleep Obfuscation)** Implement memory encryption/decryption during sleep (`core/evasion.c` or new file). Requires wrappers for sleep functions (e.g., `NtDelayExecution`) and memory protection syscalls.
    *   *Constraint:* Must integrate with existing syscall wrappers. Encryption should be simple (e.g., XOR) for MVP.
*   **(Task F5: String Obfuscation)** Implement simple string obfuscation (e.g., XORed strings, stack-based construction) for sensitive strings like "ntdll.dll", "AmsiScanBuffer", etc. Create `include/obfuscate.h` and update usages.
*   **(Task F6: Payload Handling)** Replace placeholder `raw_reflective_dll` array in `core/loader.c` with a mechanism to embed or load the payload (e.g., from resource, appended data, remote source - latter requires network syscalls).
*   **(Task F7: CI/CD & Testing Script)** Create a script (e.g., Python, PowerShell) to:
    1.  Compile a test Reflective DLL (simple MessageBox).
    2.  Convert the DLL to a C header file (`payload.h`).
    3.  Compile the PhantomEdge loader (Release, No-CRT) including `payload.h`.
    4.  Execute the compiled loader on a test VM (requires VM interaction/API).
    5.  Check for MessageBox appearance and absence of EDR alerts (requires EDR log scraping or specific checks).
    *   *Constraint:* Script should be configurable for different test environments/EDRs. Must automate the build using CMake.
*   **(Task F8: Advanced Evasion)** Implement additional evasion techniques (Thread Stack Spoofing, extended unhooking, etc.) based on `rules.mdc` roadmap. 