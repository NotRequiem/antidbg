#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
    DEBUG_QUERY_INFORMATION)

#define ObjectAllTypesInformation 3
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define DEBUG_OBJECT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

#ifdef __cplusplus
extern "C" {
#endif

    bool CheckNtQueryObject();

#ifdef __cplusplus
}
#endif