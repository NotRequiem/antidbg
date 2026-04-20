#include "procdbgport.h"
#include "..\core\syscall.h"

bool __adbg_debug_port(const HANDLE process_handle)
{
    DWORD_PTR debug_port = 0;

    const NTSTATUS status = DbgNtQueryInformationProcess(
        process_handle,
        ProcessDebugPort,
        &debug_port,
        sizeof(debug_port),
        NULL);

    if (status == 0x00000000 && debug_port != 0) {
        return true;
    }

    return false;
}
