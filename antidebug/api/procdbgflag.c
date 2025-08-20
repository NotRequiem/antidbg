#include "procdbgflag.h"
#include "..\core\syscall.h"

bool DebugFlags(const HANDLE hProcess) 
{
    DWORD dwProcessDebugFlags = 0, dwReturned;
    const DWORD ProcessDebugFlags = 0x1f;
    const NTSTATUS status = DbgNtQueryInformationProcess(
        hProcess,
        ProcessDebugFlags,
        &dwProcessDebugFlags,
        sizeof(DWORD),
        &dwReturned);
    return ((NTSTATUS)(status) >= 0) && (0 == dwProcessDebugFlags);
}