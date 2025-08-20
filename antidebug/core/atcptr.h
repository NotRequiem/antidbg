#pragma once

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h> 
#include <tlhelp32.h>
#include <intrin.h> 

#pragma comment(lib, "ntdll.lib")

#define DbgBreakPoint_FUNC_SIZE 0x2
#define DbgUiRemoteBreakin_FUNC_SIZE 0x54
#define NtContinue_FUNC_SIZE 0x18

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct _SYSTEM_THREAD_INFORMATION {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        KPRIORITY Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        ULONG WaitReason;
    } SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

    void __stdcall clb(PVOID DllHandle, DWORD reason, PVOID Reserved);

    bool StartAttachProtection(void);

#ifdef __cplusplus
}
#endif