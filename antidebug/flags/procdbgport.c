#include "procdbgport.h"
#include "..\core\syscall.h"

bool CheckNtQueryInformationProcess(const HANDLE hProcess)
{
    DWORD dwProcessDebugPort = 0, dwReturned;
    const NTSTATUS status = DbgNtQueryInformationProcess(
        hProcess,
        ProcessDebugPort,
        &dwProcessDebugPort,
        sizeof(DWORD),
        &dwReturned);
    return ((NTSTATUS)(status) >= 0) && (-1 == (int)dwProcessDebugPort);
}
