// In Development

#include <Windows.h>
#include <stdbool.h>

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
} MEMORY_INFORMATION_CLASS;

typedef union _PSAPI_WORKING_SET_BLOCK {
    ULONG Flags;
    struct {
        ULONG Protection : 5;
        ULONG ShareCount : 3;
        ULONG Shared : 1;
        ULONG Reserved : 3;
        ULONG VirtualPage : 20;
    };
} PSAPI_WORKING_SET_BLOCK, * PPSAPI_WORKING_SET_BLOCK;

typedef struct _MEMORY_WORKING_SET_LIST
{
    ULONG NumberOfPages;
    PSAPI_WORKING_SET_BLOCK WorkingSetList[1];
} MEMORY_WORKING_SET_LIST, * PMEMORY_WORKING_SET_LIST;

// Declaration for NtQueryVirtualMemory
NTSTATUS NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

// Function to check if the program is being debugged
bool IsDebugged()
{
#ifndef _WIN64
    NTSTATUS status;
    PBYTE pMem = NULL;
    DWORD dwMemSize = 0;

    do
    {
        dwMemSize += 0x1000;
        pMem = (PBYTE)_malloca(dwMemSize);
        if (!pMem)
            return false;

        memset(pMem, 0, dwMemSize);
        status = NtQueryVirtualMemory(
            GetCurrentProcess(),
            NULL,
            MemoryWorkingSetList,
            pMem,
            dwMemSize,
            NULL);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    PMEMORY_WORKING_SET_LIST pWorkingSet = (PMEMORY_WORKING_SET_LIST)pMem;
    for (ULONG i = 0; i < pWorkingSet->NumberOfPages; i++)
    {
        DWORD dwAddr = pWorkingSet->WorkingSetList[i].VirtualPage << 0x0C;
        DWORD dwEIP = 0;

        __asm
        {
            push eax
            call $ + 5
            pop eax
            mov dwEIP, eax
            pop eax
        }

        if (dwAddr == (dwEIP & 0xFFFFF000))
            return (pWorkingSet->WorkingSetList[i].Shared == 0) || (pWorkingSet->WorkingSetList[i].ShareCount == 0);
    }
#endif // _WIN64
    return false;
}
