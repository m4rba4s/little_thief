cmake_minimum_required(VERSION 3.15)
project(PhantomEdgeFuzzer C)

# Source files
set(FUZZER_SOURCES
    fuzzer_main.c
    pe_mutator.c
    crash_handler.c
    test_harness.c
)

# Create executable
add_executable(pe_fuzzer ${FUZZER_SOURCES})

# Include directories
target_include_directories(pe_fuzzer PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Compiler options
if(MSVC)
    target_compile_options(pe_fuzzer PRIVATE /W4 /WX)
    # Enable DEP and ASLR for fuzzer itself
    target_link_options(pe_fuzzer PRIVATE /DYNAMICBASE /NXCOMPAT)
endif()

# Link libraries
target_link_libraries(pe_fuzzer PRIVATE
    kernel32.lib
    ntdll.lib
    dbghelp.lib  # For crash dump generation
) 