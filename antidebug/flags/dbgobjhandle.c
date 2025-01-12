#include "dbgobjhandle.h"
#include "..\core\syscall.h"

bool IsDebuggerPresent_DebugObjectHandle(const HANDLE hProcess) 
{
    HANDLE hProcessDebugObject = 0;
    const DWORD ProcessDebugObjectHandle = 0x1e;
    DWORD dwReturned;
    const NTSTATUS status = DbgNtQueryInformationProcess(
        hProcess,
        ProcessDebugObjectHandle,
        &hProcessDebugObject,
        sizeof(HANDLE),
        &dwReturned);
        return ((NTSTATUS)(status) >= 0) && (hProcessDebugObject != 0);
}