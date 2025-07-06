#include "readstck.h"
#include "..\core\syscall.h"

bool ReadMemoryStack() {
    PVOID stack_address = NULL;
    SIZE_T number_of_bytes_read;

    PVOID own_stack_address = &stack_address;
    CONST HANDLE hProcess = GetCurrentProcess();
    NTSTATUS status = DbgNtReadVirtualMemory(hProcess, own_stack_address, &stack_address, sizeof(PVOID), &number_of_bytes_read);
    DbgNtClose(hProcess);

    if (!((NTSTATUS)(status) >= 0) || number_of_bytes_read != sizeof(PVOID)) {
        return true;
    }

    return false;
}