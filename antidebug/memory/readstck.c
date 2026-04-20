#include "readstck.h"
#include "..\core\syscall.h"

bool __adbg_stack_memory() 
{
    PVOID stack_address = NULL;
    SIZE_T number_of_bytes_read;

    PVOID own_stack_address = &stack_address;
    const HANDLE process_handle = (HANDLE)(-1LL); // we dont pass a process handle by argument in the function prologue on purpose
    const NTSTATUS status = DbgNtReadVirtualMemory(process_handle, own_stack_address, &stack_address, sizeof(PVOID), &number_of_bytes_read);
    DbgNtClose(process_handle);

    if (!((NTSTATUS)(status) >= 0) || number_of_bytes_read != sizeof(PVOID)) {
        return true;
    }

    return false;
}