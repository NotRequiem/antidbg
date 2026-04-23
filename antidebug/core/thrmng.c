#include "thrmng.h"
#include "syscall.h"

static inline ULONG _ntstatus_to_dos(const NTSTATUS status)
{
    if (status == STATUS_SUCCESS)
        return ERROR_SUCCESS;

    switch (status)
    {
    case STATUS_ACCESS_DENIED:
        return ERROR_ACCESS_DENIED;

    case STATUS_INVALID_HANDLE:
        return ERROR_INVALID_HANDLE;

    case STATUS_INVALID_PARAMETER:
        return ERROR_INVALID_PARAMETER;

    case STATUS_NO_MEMORY:
    case STATUS_INSUFFICIENT_RESOURCES:
        return ERROR_NOT_ENOUGH_MEMORY;

    case STATUS_NOT_SUPPORTED:
        return ERROR_NOT_SUPPORTED;

    case STATUS_PROCESS_IS_TERMINATING:
        return ERROR_PROCESS_ABORTED;

    case STATUS_PRIVILEGE_NOT_HELD:
        return ERROR_PRIVILEGE_NOT_HELD;

    case STATUS_ACCESS_VIOLATION:
        return ERROR_NOACCESS;

    case STATUS_STACK_OVERFLOW:
        return ERROR_STACK_OVERFLOW;
    }

    // if already a Win32-style error
    if ((status & 0x20000000) != 0)
        return (ULONG)status;

    return ERROR_MR_MID_NOT_FOUND; // 317
}

HANDLE DbgCreateThread(
    const HANDLE process_handle,
    const SIZE_T dwStackSize,
    const LPTHREAD_START_ROUTINE lpStartAddress,
    const LPVOID lpParameter,
    const DWORD dwCreationFlags,
    const LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId)
{
    HANDLE thread_handle = NULL;

    const DWORD dwMergedFlags = dwCreationFlags |
        THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER |
        THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE;

#pragma warning (disable : 4152)
    const NTSTATUS status_create = DbgNtCreateThreadEx(
        &thread_handle,
        THREAD_ALL_ACCESS,
        NULL,
        process_handle,
        lpStartAddress,
        lpParameter,
        dwMergedFlags,
        0,
        dwStackSize,
        dwStackSize,
        (PPS_ATTRIBUTE_LIST)lpAttributeList);
#pragma warning (default : 4152)

    if (status_create < 0) {
        SetLastError(_ntstatus_to_dos(status_create));
        return NULL;
    }

    // force hook in two calls
    DbgNtSetInformationThread(thread_handle, ThreadHideFromDebugger, NULL, 0);

    if (lpThreadId)
    {
        struct {
            NTSTATUS ExitStatus;
            PVOID TebBaseAddress;
            ULONG_PTR ClientId[2]; // ClientId[0] = Process ID, ClientId[1] = Thread ID
            ULONG_PTR AffinityMask;
            LONG Priority;
            LONG BasePriority;
        } tbi = { 0 };

        if (DbgNtQueryInformationThread(thread_handle, 0, &tbi, sizeof(tbi), NULL) >= 0)
        {
            *lpThreadId = (DWORD)tbi.ClientId[1];
        }
        else
        {
            *lpThreadId = 0;
        }
    }

    return thread_handle;
}