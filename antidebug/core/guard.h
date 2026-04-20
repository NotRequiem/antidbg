#pragma once

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <tlhelp32.h>
#include <intrin.h> 
#include <stdbool.h>
#include <wchar.h>
#include <strsafe.h>

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

#ifndef OBJ_CASE_INSENSITIVE
    #define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#if defined(__clang__) || defined(__GNUC__)
    #define _force_inline __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
    #define _force_inline __forceinline
#else
    #define _force_inline inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

    void __stdcall __clb(PVOID DllHandle, DWORD reason, PVOID Reserved);

    bool __setup_protection(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif