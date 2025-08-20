cmake_minimum_required(VERSION 3.15)
project(antidebug LANGUAGES C)

# Require x64
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "This project targets x64 only. Please use a 64-bit toolchain/generator.")
endif()

# Options
option(BUILD_SHARED_LIBS "Build antidebug as a shared library (DLL)" OFF)
option(BUILD_EXAMPLE "Build a small example executable (if you add one)" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF) # Windows native code; switch on if you build PIC

# Collect sources
file(GLOB_RECURSE ADBG_SOURCES
    "${CMAKE_SOURCE_DIR}/*.c"
    "${CMAKE_SOURCE_DIR}/api/*.c"
    "${CMAKE_SOURCE_DIR}/asm/*.c"
    "${CMAKE_SOURCE_DIR}/core/*.c"
    "${CMAKE_SOURCE_DIR}/exceptions/*.c"
    "${CMAKE_SOURCE_DIR}/flags/*.c"
    "${CMAKE_SOURCE_DIR}/memory/*.c"
    "${CMAKE_SOURCE_DIR}/object/*.c"
)

if (ADBG_SOURCES STREQUAL "")
    message(FATAL_ERROR "No C sources found. Make sure this CMakeLists.txt is at project root.")
endif()

# Create library target
add_library(antidebug ${ADBG_SOURCES})

# Public include directory so your #include "adbg.h" and subfolder includes work
target_include_directories(antidebug
    PUBLIC
        ${CMAKE_SOURCE_DIR}
)

# Compiler-specific flags
if(MSVC)
    # high warning level and disable 4201 (anonymous struct/union) which your code intentionally disables via pragma
    target_compile_options(antidebug PRIVATE /W4 /wd4201 /wd4996)
    # enable multi-processor compilation if available
    target_compile_options(antidebug PRIVATE /MP)
else()
    # GCC / Clang flags
    target_compile_options(antidebug PRIVATE -Wall -Wextra -Wshadow -Wno-unused-parameter -Wno-missing-field-initializers)
    # prefer narrow aliases warnings off if your code uses pointer-casts heavily
    target_compile_options(antidebug PRIVATE -fno-strict-aliasing)
endif()

# Link typical windows libs (kernel32 is the must)
target_link_libraries(antidebug PRIVATE kernel32 user32)

# If you want a small example binary (optional)
if(BUILD_EXAMPLE)
    # user must provide example/main.c (not included in repo by default)
    add_executable(adbg_example examples/main.c)
    target_link_libraries(adbg_example PRIVATE antidebug)
    target_include_directories(adbg_example PRIVATE ${CMAKE_SOURCE_DIR})
endif()

# Install rules (optional)
install(TARGETS antidebug
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/
    DESTINATION include/antidebug
    FILES_MATCHING PATTERN "*.h"
)

# Helpful summary
message(STATUS "antidebug: building ${BUILD_SHARED_LIBS?\"shared\" : \"static\"} library for x64")
message(STATUS "Sources: ${ADBG_SOURCES}")
