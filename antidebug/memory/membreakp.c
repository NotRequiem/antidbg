#include "membreakp.h"
#include "..\core\syscall.h"

bool MemoryBreakpoint(const HANDLE hProcess)
{
    SYSTEM_INFO SystemInfo = { 0 };
    ULONG OldProtect = 0;
    PVOID pAllocation = NULL;
    SIZE_T RegionSize;

    GetSystemInfo(&SystemInfo);
    RegionSize = SystemInfo.dwPageSize;

    NTSTATUS status = DbgNtAllocateVirtualMemory(hProcess, &pAllocation, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!((NTSTATUS)(status) >= 0) || pAllocation == NULL)
        return FALSE;

    RtlFillMemory(pAllocation, 1, 0xC3);

    status = DbgNtProtectVirtualMemory(hProcess, &pAllocation, &RegionSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect);
    if (!((NTSTATUS)(status) >= 0))
    {
        DbgNtFreeVirtualMemory(hProcess, &pAllocation, &RegionSize, MEM_RELEASE);
        return FALSE;
    }

    __try
    {
        ((void(*)())pAllocation)();
    }
    __except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        DbgNtFreeVirtualMemory(hProcess, &pAllocation, &RegionSize, MEM_RELEASE);
        return FALSE;
    }

    DbgNtFreeVirtualMemory(hProcess, &pAllocation, &RegionSize, MEM_RELEASE);
    return TRUE;
}
