cmake_minimum_required(VERSION 3.15)
project(antidebug LANGUAGES C)

if(NOT WIN32)
  message(FATAL_ERROR "This project targets Windows systems only.")
endif()

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

# define the directories we actually want to compile (explicitly avoiding "archived/")
set(ACTIVE_SOURCE_DIRS
    "${CMAKE_SOURCE_DIR}"
    "${CMAKE_SOURCE_DIR}/api"
    "${CMAKE_SOURCE_DIR}/asm"
    "${CMAKE_SOURCE_DIR}/core"
    "${CMAKE_SOURCE_DIR}/exceptions"
    "${CMAKE_SOURCE_DIR}/flags"
    "${CMAKE_SOURCE_DIR}/memory"
    "${CMAKE_SOURCE_DIR}/object"
)

# standard GLOB to avoid recursing into /archived
set(ADBG_SOURCES "")
foreach(DIR IN LISTS ACTIVE_SOURCE_DIRS)
    file(GLOB DIR_SOURCES "${DIR}/*.c")
    list(APPEND ADBG_SOURCES ${DIR_SOURCES})
endforeach()

if (NOT ADBG_SOURCES)
    message(FATAL_ERROR "No C sources found. Make sure this CMakeLists.txt is at project root.")
endif()

if(MSVC)
    # MSVC (cl.exe) uses MASM (ml64.exe)
    enable_language(ASM_MASM)
    set(ASM_SOURCE "${CMAKE_SOURCE_DIR}/core/syscall-core.asm")
    set_source_files_properties(${ASM_SOURCE} PROPERTIES LANGUAGE ASM_MASM)
    list(APPEND ADBG_SOURCES ${ASM_SOURCE})
    message(STATUS "Compiler: MSVC detected. Using MASM -> ${ASM_SOURCE}")
else()
    # GCC / MinGW / Clang uses GNU AT&T Assembly (.S)
    enable_language(ASM)
    set(ASM_SOURCE "${CMAKE_SOURCE_DIR}/core/syscall-core.S")
    set_source_files_properties(${ASM_SOURCE} PROPERTIES LANGUAGE ASM)
    list(APPEND ADBG_SOURCES ${ASM_SOURCE})
    message(STATUS "Compiler: GCC/Clang/MinGW detected. Using GNU AS -> ${ASM_SOURCE}")
endif()

# Create library target
add_library(antidebug ${ADBG_SOURCES})

# public include directory so #include "adbg.h" and subfolder includes work
target_include_directories(antidebug PUBLIC ${CMAKE_SOURCE_DIR})

# compiler-specific flags
if(MSVC)
    # high warning level and disable 4201 (anonymous struct/union)
    target_compile_options(antidebug PRIVATE /W4 /wd4201 /wd4996)
    # enable multi-processor compilation if available
    target_compile_options(antidebug PRIVATE /MP)
    
    # Link Time Code Generation (LTCG) for Release 
    target_compile_options(antidebug PRIVATE $<$<CONFIG:Release>:/GL>)

    # Linker flags
    target_link_options(antidebug PUBLIC
        /MANIFEST
        /NXCOMPAT
        /DYNAMICBASE
        /DEBUG
        /MACHINE:X64
        /OPT:REF
        /INCREMENTAL:NO
        /SUBSYSTEM:CONSOLE
        "/MANIFESTUAC:level='asInvoker' uiAccess='false'"
        /ERRORREPORT:PROMPT
        /NOLOGO
        /TLBID:1
    )
    
    # Release-specific linker flag for Link Time Code Generation
    target_link_options(antidebug PUBLIC $<$<CONFIG:Release>:/LTCG>)
else()
    # GCC / Clang / MinGW flags
    target_compile_options(antidebug PRIVATE 
        -Wall 
        -Wextra 
        -Wshadow 
        -Wno-unused-parameter 
        -Wno-missing-field-initializers
        -fno-strict-aliasing
    )
endif()

# Link typical windows libs (kernel32 is the must)
target_link_libraries(antidebug PRIVATE 
    kernel32 user32 gdi32 winspool comdlg32 advapi32 
    shell32 ole32 oleaut32 uuid odbc32 odbccp32
)

# If you want a small example binary (optional)
if(BUILD_EXAMPLE)
    # user must provide a int main function
    add_executable(antidebug_exe adbg.c)
    target_link_libraries(antidebug_exe PRIVATE antidebug)
    target_include_directories(antidebug_exe PRIVATE ${CMAKE_SOURCE_DIR})
endif()

# rules (optional)
install(TARGETS antidebug
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/
    DESTINATION include/antidebug
    FILES_MATCHING PATTERN "*.h"
)

# readable lib type string for summary
if(BUILD_SHARED_LIBS)
    set(LIB_TYPE "shared")
else()
    set(LIB_TYPE "static")
endif()

message(STATUS "antidebug: building ${LIB_TYPE} library for x64")