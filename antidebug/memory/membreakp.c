#include "membreakp.h"

/*
bool MemoryBreakpoint()
{
    DWORD dwOldProtect = 0;
    SYSTEM_INFO SysInfo = { 0 };

    // Get system information to determine the page size
    GetSystemInfo(&SysInfo);

    // Allocate a page of memory with read-write-execute permissions
    PVOID pPage = VirtualAlloc(NULL, SysInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Check if the allocation was successful
    if (NULL == pPage)
        return false;

    // Set the first byte of the allocated memory to the RET instruction (0xC3)
    PBYTE pMem = (PBYTE)pPage;
    *pMem = 0xC3;

    // Make the page a guard page
    if (!VirtualProtect(pPage, SysInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect))
    {
        // Cleanup and return false if setting the guard page fails
        VirtualFree(pPage, NULL, MEM_RELEASE);
        return false;
    }

    __try
    {
        // Raise an exception to trigger the guard page violation
        RaiseException(STATUS_GUARD_PAGE_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, NULL);

        // If the exception is not triggered, return false
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // Exception handler: If an exception occurs, it means the guard page was hit
        // Cleanup and return true (indicating the presence of a debugger)
        VirtualFree(pPage, NULL, MEM_RELEASE);
        return true;
    }
}
*/

bool MemoryBreakpoint()
{
    UCHAR* pMem = NULL;
    SYSTEM_INFO SystemInfo = { 0 };
    DWORD OldProtect = 0;
    PVOID pAllocation = NULL;

    GetSystemInfo(&SystemInfo);

    pAllocation = VirtualAlloc(NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pAllocation == NULL)
        return FALSE;

    RtlFillMemory(pAllocation, 1, 0xC3);

    if (VirtualProtect(pAllocation, SystemInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect) == 0)
        return FALSE;

    __try
    {
        ((void(*)())pAllocation)();
    }
    __except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        VirtualFree(pAllocation, 0, MEM_RELEASE);
        return FALSE;
    }

    VirtualFree(pAllocation, 0, MEM_RELEASE);
    return TRUE;
}
