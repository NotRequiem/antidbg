#pragma once

#include <windows.h>
#include <stdbool.h>

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)

#define SE_DEBUG_PRIVILEGE 20L

#ifdef __cplusplus
extern "C" {
#endif

    bool __adbg_system_debug_control(const HANDLE process_handle);
    
#ifdef __cplusplus
}
#endif