#include "procdbgport.h"
#include "..\core\syscall.h"

bool DebugPort(const HANDLE hProcess)
{
    DWORD_PTR dwDebugPort = 0;
    const NTSTATUS status = DbgNtQueryInformationProcess(
        hProcess,
        ProcessDebugPort,
        &dwDebugPort,
        sizeof(dwDebugPort),
        NULL);

    if (status == 0x00000000 && dwDebugPort != 0) {
        return TRUE;
    }

    return FALSE;
}
