#pragma once

#include <windows.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

    HANDLE SpectrumCreateThread(
        const HANDLE hProcess,
        const SIZE_T dwStackSize,
        const LPTHREAD_START_ROUTINE lpStartAddress,
        const LPVOID lpParameter,
        const DWORD dwCreationFlags,
        const LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        LPDWORD lpThreadId);

#ifdef __cplusplus
}
#endif