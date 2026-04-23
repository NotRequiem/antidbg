#include "dbgobjhandle.h"
#include "..\core\syscall.h"

bool __adbg_object_handle(const HANDLE process_handle) 
{
    HANDLE debug_object = NULL;
    const NTSTATUS status = DbgNtQueryInformationProcess(
        process_handle,
        ProcessDebugObjectHandle,
        &debug_object,
        sizeof(HANDLE),
        (PULONG)1
    );

    if (status != (NTSTATUS)STATUS_ACCESS_VIOLATION) {
        return true;
    }

    if (debug_object != NULL) {
        return true;
    }

    return false;
}