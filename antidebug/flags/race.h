#pragma once

#include <windows.h>
#include <stdbool.h>

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef CONTEXT_DEBUG_REGISTERS
    #define CONTEXT_DEBUG_REGISTERS (CONTEXT_AMD64 | 0x00000010L)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct _RaceContext {
        PCONTEXT ContextPtr;
        volatile bool Run;
    } RaceContext;

    bool __adbg_race_condition(const HANDLE thread_handle);

#ifdef __cplusplus
}
#endif

