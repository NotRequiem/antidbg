#pragma once

#include <windows.h>

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef OBJ_CASE_INSENSITIVE
    #define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifdef __cplusplus
extern "C" {
#endif

    LONG CALLBACK __global_handler(PEXCEPTION_POINTERS exception_info);

#ifdef __cplusplus
}
#endif