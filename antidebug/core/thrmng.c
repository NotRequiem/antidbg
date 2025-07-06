#include "thrmng.h"
#include "syscall.h"

HANDLE SpectrumCreateThread(
    const HANDLE hProcess,
    const SIZE_T dwStackSize,
    const LPTHREAD_START_ROUTINE lpStartAddress,
    const LPVOID lpParameter,
    const DWORD dwCreationFlags,
    const LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId)
{
    HANDLE hThread = NULL;
#pragma warning (disable : 4152)
    const NTSTATUS statusCreate = DbgNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        0,
        dwStackSize,
        dwStackSize,
        (PPS_ATTRIBUTE_LIST)lpAttributeList);
#pragma warning (default : 4152)

    if (statusCreate < 0) {
        SetLastError(statusCreate);
        return NULL;
    }

    const NTSTATUS statusHide = DbgNtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, 0);
    if (!((NTSTATUS)(statusHide) >= 0)) {
#ifdef _DEBUG
        printf("Failed to hide thread from debugger. Status: 0x%08X\n", statusHide);
#endif
    }

    if (lpThreadId)
        *lpThreadId = GetThreadId(hThread);

    return hThread;
}