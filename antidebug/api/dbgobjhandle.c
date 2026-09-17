#include "dbgobjhandle.h"
#include "..\core\syscall.h"

bool __adbg_object_handle(const HANDLE process_handle)
{
    HANDLE debug_object = NULL;
    ULONG return_length = 0;

    const NTSTATUS status = DbgNtQueryInformationProcess(
        process_handle,
        ProcessDebugObjectHandle,
        &debug_object,
        sizeof(debug_object),
        &return_length
    );

    if (status == (NTSTATUS)0xC0000353L) // STATUS_PORT_NOT_SET
    {
        return false;
    }

    if (status == STATUS_SUCCESS)
    {
        return debug_object != NULL;
    }

    return false;
}
