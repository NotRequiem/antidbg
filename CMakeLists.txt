cmake_minimum_required(VERSION 3.16)
project(AntiDebug C ASM_MASM)

# for direct syscalls
enable_language(ASM_MASM)

file(GLOB_RECURSE AD_SOURCES
     CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/antidebug/*.c"
     "${CMAKE_CURRENT_SOURCE_DIR}/antidebug/*.asm"
)

file(GLOB_RECURSE AD_HEADERS
     CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/antidebug/*.h"
)

add_library(antidebug_lib STATIC
    ${AD_SOURCES}
    ${AD_HEADERS}        # not strictly needed; helps IDEs show headers
)

target_include_directories(antidebug_lib PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/antidebug"
)