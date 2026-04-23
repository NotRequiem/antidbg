#include "procdbgflag.h"
#include "..\core\syscall.h"

bool __adbg_debug_flags(const HANDLE process_handle) 
{
    DWORD debug_flags = 0, returned;

    const NTSTATUS status = DbgNtQueryInformationProcess(
        process_handle,
        ProcessDebugFlags,
        &debug_flags,
        sizeof(DWORD),
        &returned);

    return ((NTSTATUS)(status) >= 0) && (0 == debug_flags);
}