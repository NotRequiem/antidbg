cmake_minimum_required(VERSION 3.16)
project(antidebug LANGUAGES C)

if(NOT WIN32)
  message(FATAL_ERROR "This project targets Windows systems only.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "This project targets x64 only. Please use a 64-bit toolchain.")
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  message(FATAL_ERROR 
    "GCC does not support Microsoft Structured Exception Handling (__try/__except) in C.\n"
    "Please use Clang (clang/clang-cl) or MSVC to compile this library."
  )
endif()

option(BUILD_SHARED_LIBS "Build antidebug as a shared library (DLL)" OFF)
option(BUILD_EXAMPLE "Build a test runner executable" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(ADBG_SOURCES
    api/dbgobjhandle.c
    api/dbgpresent.c
    api/outdbgstring.c
    api/procdbgflag.c
    api/procdbgport.c
    api/rdbgpresent.c
    api/setdbgfltstate.c
    api/sysdbgcontrol.c
    api/sysimpl.c
    asm/ice.c
    asm/instcnt.c
    asm/int2d.c
    asm/int3.c
    asm/lbr_btf.c
    asm/popf.c
    asm/prehop.c
    asm/stckseg.c
    core/callback.c
    core/debug.c
    core/guard.c
    core/handler.c
    core/module.c
    core/monitor.c
    core/random.c
    core/thrmng.c
    exceptions/pgexcbp.c
    exceptions/raiseexc.c
    flags/crtlevent.c
    flags/duphnd.c
    flags/job.c
    flags/kerneldbg.c
    flags/loadlib.c
    flags/ntglobalflag.c
    flags/prntproc.c
    flags/race.c
    flags/suspend.c
    flags/timing.c
    flags/window.c
    memory/heap.c
    memory/hwbreakp.c
    memory/mapview.c
    memory/membreak.c
    memory/peb.c
    memory/readstck.c
    memory/vrtalloc.c
    memory/workset.c
    object/clshandle.c
    object/dbgobj.c
    object/device.c
    object/opnproc.c
    object/prothnd.c
    adbg.c # Core checks definition (without int main())
)

if(MSVC AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    # Pure MSVC (cl.exe) uses MASM
    enable_language(ASM_MASM)
    set(ASM_SOURCE "core/syscall-core.asm")
    set_source_files_properties(${ASM_SOURCE} PROPERTIES LANGUAGE ASM_MASM)
    list(APPEND ADBG_SOURCES ${ASM_SOURCE})
else()
    # Clang, clang-cl, or MinGW Clang can assemble GNU AT&T / GAS syntax (.S)
    enable_language(ASM)
    set(ASM_SOURCE "core/syscall-core.S")
    set_source_files_properties(${ASM_SOURCE} PROPERTIES LANGUAGE ASM)
    list(APPEND ADBG_SOURCES ${ASM_SOURCE})
endif()

add_library(antidebug ${ADBG_SOURCES})
target_include_directories(antidebug PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

if(MSVC)
    target_compile_options(antidebug PRIVATE 
        /W4 /wd4201 /wd4996
        $<$<C_COMPILER_ID:MSVC>:/MP> # /MP only for cl.exe
    )

    if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
        target_compile_options(antidebug PRIVATE $<$<CONFIG:Release>:/GL>)
    elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
        target_compile_options(antidebug PRIVATE $<$<CONFIG:Release>:-flto>)
    endif()

    if(BUILD_SHARED_LIBS)
        target_link_options(antidebug PRIVATE
            /NXCOMPAT
            /DYNAMICBASE
            /MACHINE:X64
            /OPT:REF
            $<$<AND:$<CONFIG:Release>,$<C_COMPILER_ID:MSVC>>:/LTCG>
        )
    endif()
else()
    # Clang with GNU Driver
    target_compile_options(antidebug PRIVATE 
        -Wall 
        -Wextra 
        -Wshadow 
        -Wno-unused-parameter 
        -Wno-missing-field-initializers
        -fno-strict-aliasing
        -fms-extensions      
        -msse4.2          
        -mstackrealign
    )
endif()

target_link_libraries(antidebug PRIVATE 
    kernel32 
    user32 
    advapi32 
    ntdll  
    psapi  
)

if(BUILD_EXAMPLE)
    # The example runner must live in its own file (e.g. example/main.c)
    add_executable(antidebug_runner example/main.c)
    target_link_libraries(antidebug_runner PRIVATE antidebug)
    
    if(MSVC)
        target_link_options(antidebug_runner PRIVATE 
            /SUBSYSTEM:CONSOLE
            /NXCOMPAT
            /DYNAMICBASE
        )
    endif()
endif()