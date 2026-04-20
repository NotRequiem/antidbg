#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008

#ifndef DEBUG_ALL_ACCESS
    #define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
        DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
        DEBUG_QUERY_INFORMATION)
#endif

#define ObjectAllTypesInformation 3
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define DEBUG_OBJECT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_BUFFER_OVERFLOW           ((NTSTATUS)0x80000005L)

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    bool __adbg_query_object();

#ifdef __cplusplus
}
#endif