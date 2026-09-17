#pragma once

#include <windows.h>
#include <stdbool.h>

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define VIEW_SIZE_12_TIB (12ULL << 40)

#ifdef __cplusplus
extern "C" {
#endif

    bool __adbg_freeze_debugger(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif
