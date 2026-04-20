#include "membreak.h"
#include "..\core\syscall.h"

bool __adbg_memory_breakpoint(const HANDLE process_handle)
{
    SYSTEM_INFO system_info = { 0 };
    ULONG old_protection = 0;
    PVOID allocation = NULL;
    SIZE_T region_size;

    GetSystemInfo(&system_info);
    region_size = system_info.dwPageSize;

    NTSTATUS status = DbgNtAllocateVirtualMemory(process_handle, &allocation, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!((NTSTATUS)(status) >= 0) || allocation == NULL)
        return false;

    RtlFillMemory(allocation, 1, 0xC3);

    status = DbgNtProtectVirtualMemory(process_handle, &allocation, &region_size, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old_protection);
    if (!((NTSTATUS)(status) >= 0))
    {
        DbgNtFreeVirtualMemory(process_handle, &allocation, &region_size, MEM_RELEASE);
        return false;
    }

    __try
    {
        ((void(*)())allocation)();
    }
    __except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        DbgNtFreeVirtualMemory(process_handle, &allocation, &region_size, MEM_RELEASE);
        return false;
    }

    DbgNtFreeVirtualMemory(process_handle, &allocation, &region_size, MEM_RELEASE);
    return true;
}
