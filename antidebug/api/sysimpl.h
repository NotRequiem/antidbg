#pragma once

#include <windows.h>
#include <stdbool.h>

#ifndef STATUS_SUCCESS
    #define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_NOT_IMPLEMENTED
    #define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#endif

#ifndef STATUS_INVALID_INFO_CLASS
    #define STATUS_INVALID_INFO_CLASS        ((NTSTATUS)0xC0000003L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
    #define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#endif

#define SystemKernelDebuggerInformationClass  35
#define SystemBootEnvironmentInformationClass 90
#define SystemCodeIntegrityInformationClass   103

#ifdef __cplusplus
extern "C" {
#endif

    bool __adbg_check_syscalls();

#ifdef __cplusplus
}
#endif