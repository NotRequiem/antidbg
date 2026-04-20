#pragma once

#include <windows.h>
#include <stdbool.h>
#include <wchar.h>

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xC000003AL)
#define STATUS_ACCESS_DENIED         ((NTSTATUS)0xC0000022L)

#ifndef OBJ_CASE_INSENSITIVE
    #define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifdef __cplusplus
extern "C" {
#endif

    bool __adbg_device();

#ifdef __cplusplus
}
#endif