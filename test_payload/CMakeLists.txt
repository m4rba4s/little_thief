cmake_minimum_required(VERSION 3.15)

project(TestPayload C)

# Source files
set(PAYLOAD_SOURCES
    src/dllmain.c
    src/reflective_loader.c
)

# Include directory
include_directories(include)

# Add the library
add_library(test_payload SHARED ${PAYLOAD_SOURCES})

# Explicitly define target architecture macros for ntdef.h for this target
# This must come AFTER add_library for test_payload
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(test_payload PRIVATE _AMD64_)
    message(STATUS "TestPayload: Forcing _AMD64_ definition as target architecture is 64-bit.")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_compile_definitions(test_payload PRIVATE _X86_)
    message(STATUS "TestPayload: Forcing _X86_ definition as target architecture is 32-bit.")
endif()

# Target include directories (redundant with include_directories but good practice)
target_include_directories(test_payload PRIVATE include)

# Set properties for DLL
set_target_properties(test_payload PROPERTIES
    PREFIX "" # Don't add 'lib' prefix
    SUFFIX ".dll"
    OUTPUT_NAME "test_payload"
)

# Linker flags (MSVC example)
if(MSVC)
    # Export the ReflectiveLoader function
    target_link_options(test_payload PRIVATE /EXPORT:ReflectiveLoader)
    # Ensure standard libraries are linked (unlike the main loader)
    # This is usually default for shared libs, but explicitly state if needed
endif()

message(STATUS "Test Payload CMake Configuration Loaded") 