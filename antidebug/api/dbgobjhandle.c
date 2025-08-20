#include "dbgobjhandle.h"
#include "..\core\syscall.h"

bool DebugObjectHandle(const HANDLE hProcess) 
{
    HANDLE hDebugObject = NULL;
    const NTSTATUS status = DbgNtQueryInformationProcess(
        hProcess,
        ProcessDebugObjectHandle,
        &hDebugObject,
        sizeof(HANDLE),
        (PULONG)1
    );

    if (status != STATUS_ACCESS_VIOLATION) {
        return TRUE;
    }

    if (hDebugObject != NULL) {
        return TRUE;
    }

    return FALSE;
}