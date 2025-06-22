cmake_minimum_required(VERSION 3.15)

project(PhantomEdge C ASM)

enable_language(ASM_MASM)

# Explicitly define target architecture macros for ntdef.h
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_compile_definitions(_AMD64_)
    message(STATUS "PhantomEdge: Forcing _AMD64_ definition as target architecture is 64-bit.")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_compile_definitions(_X86_)
    message(STATUS "PhantomEdge: Forcing _X86_ definition as target architecture is 32-bit.")
else()
    message(WARNING "PhantomEdge: Could not determine target architecture (32/64-bit) from CMAKE_SIZEOF_VOID_P.")
endif()

# Project directories
set(STUB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/stub)
set(CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

include_directories(${INCLUDE_DIR})

# Source files
set(CORE_SOURCES
    ${CORE_DIR}/utils.c
    ${CORE_DIR}/syscalls.c
    ${CORE_DIR}/syscall_stub.asm
    ${CORE_DIR}/mem.c
    ${CORE_DIR}/evasion.c
    ${CORE_DIR}/rdi.c
    ${CORE_DIR}/strategy.c
    ${CORE_DIR}/strategy_ekko.c
    ${CORE_DIR}/loader.c
)

# Add the test_payload subdirectory
add_subdirectory(test_payload)

# Add the fuzzer subdirectory (optional build)
# option(BUILD_FUZZER "Build the PE fuzzer" ON)
# if(BUILD_FUZZER)
#     add_subdirectory(fuzzer)
# endif()

# Main executable
add_executable(PhantomEdge WIN32 ${STUB_DIR}/entry.c ${CORE_SOURCES})

# Ensure test_payload.dll is in the same output directory as PhantomEdge.exe
set_target_properties(test_payload PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}
)

# Add test_payload include directory to PhantomEdge target
target_include_directories(PhantomEdge PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/test_payload/include
)

# Copy test_payload.dll next to PhantomEdge.exe after build (all configs)
add_custom_command(TARGET PhantomEdge POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:test_payload>" "$<TARGET_FILE_DIR:PhantomEdge>"
)

# --- Configuration Specific Settings ---

if(MSVC)
    message(STATUS "Configuring MSVC specific options...")
    # Compiler flags for Debug
    # /MDd: Link with Debug Multithread-DLL CRT (MSVCRTD.lib)
    # /RTC1: Enable comprehensive runtime checks (stack frames, uninitialized variables)
    # /GS: Enable buffer security check (stack canaries)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MDd /RTC1 /GS")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MDd /RTC1 /GS")

    # Compiler flags for Release
    # /O2: Optimize for speed
    # /GL: Enable Whole Program Optimization (Link-Time Code Generation)
    # /GS-: Disable buffer security check (for Release build as per project_log)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /GL /GS-")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL /GS-")

    # Linker options using generator expressions
    target_link_options(PhantomEdge PRIVATE
        # Common for WIN32 executables (no console, custom entry point)
        $<$<BOOL:${WIN32}>:/SUBSYSTEM:WINDOWS /ENTRY:RealEntry>

        # Release specific linker options
        $<$<CONFIG:Release>:/NODEFAULTLIB /DEBUG:NONE /OPT:REF /OPT:ICF /INCREMENTAL:NO /LTCG>

        # Debug specific linker options
        # MSVCRTD.lib will be linked by default due to /MDd, but we can be explicit
        # $<$<CONFIG:Debug>:msvcrtd.lib> # Это не target_link_options, а target_link_libraries
    )

    # Explicitly link CRT debug library for Debug configuration
    target_link_libraries(PhantomEdge PRIVATE $<$<CONFIG:Debug>:msvcrtd.lib>)

    # Disable /GL for loader.c
    set_source_files_properties(
        ${CMAKE_SOURCE_DIR}/core/loader.c
        PROPERTIES COMPILE_FLAGS "/GL-"
    )

else()
    # --- GCC/Clang Specific Configuration ---
    message(STATUS "Configuring GCC/Clang specific options...")
    # Using CMAKE_BUILD_TYPE for single-configuration generators
    if(NOT CMAKE_BUILD_TYPE OR (CMAKE_BUILD_TYPE STREQUAL "Release"))
        message(STATUS "Configuring for Release build (GCC/Clang)")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -fvisibility=hidden -flto -fno-stack-protector")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -fvisibility=hidden -flto -fno-stack-protector")
        target_link_options(PhantomEdge PRIVATE -s) # Strip symbols
    elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(STATUS "Configuring for Debug build (GCC/Clang)")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0") # Debug symbols, no optimization
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
    endif()
endif()

message(STATUS "Phantom Edge Final Configuration Loaded") 