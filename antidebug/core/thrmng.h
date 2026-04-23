#pragma once

#include <windows.h>
#include <stdio.h>

#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
    #define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#endif

#ifndef THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE
    #define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040
#endif

#define STATUS_SUCCESS                ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED          ((NTSTATUS)0xC0000022L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_NOT_SUPPORTED          ((NTSTATUS)0xC00000BBL)
#define STATUS_PROCESS_IS_TERMINATING ((NTSTATUS)0xC000010AL)
#define STATUS_PRIVILEGE_NOT_HELD     ((NTSTATUS)0xC0000061L)

#ifdef __cplusplus
extern "C" {
#endif

    HANDLE DbgCreateThread(
        const HANDLE process_handle,
        const SIZE_T dwStackSize,
        const LPTHREAD_START_ROUTINE lpStartAddress,
        const LPVOID lpParameter,
        const DWORD dwCreationFlags,
        const LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        LPDWORD lpThreadId);

#ifdef __cplusplus
}
#endif