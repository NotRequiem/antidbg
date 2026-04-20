#include "workset.h"
#include "..\core\syscall.h"

bool __adbg_working_set(const HANDLE process_handle)
{
    NTSTATUS status;
    PVOID memory_pointer = NULL;
    SIZE_T memory_size = 0x1000 * 0x10;
    bool debugged = false;

    do
    {
        memory_pointer = NULL;

        DbgNtAllocateVirtualMemory(
            process_handle,
            &memory_pointer,
            0,
            &memory_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!memory_pointer)
        {
            return false;
        }

        status = DbgNtQueryVirtualMemory(
            process_handle,
            NULL,
            MemoryWorkingSetList,
            memory_pointer,
            memory_size,
            NULL
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            SIZE_T free_size = 0;
            DbgNtFreeVirtualMemory(process_handle, &memory_pointer, &free_size, MEM_RELEASE);
            memory_size *= 2;
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status))
    {
        const PMEMORY_WORKING_SET_LIST_64 working_set = (PMEMORY_WORKING_SET_LIST_64)memory_pointer;

        const ULONG64 current_code_page = ((ULONG64)&__adbg_working_set) & ~0xFFFULL;

        for (ULONG64 i = 0; i < working_set->NumberOfPages; i++)
        {
            const ULONG64 dw_addr = working_set->WorkingSetList[i].VirtualPage << 12;

            if (dw_addr == current_code_page)
            {
                // If Shared == 0 or ShareCount == 0, a Copy-On-Write has occurred (likely a INT 3)
                if (working_set->WorkingSetList[i].Shared == 0 || working_set->WorkingSetList[i].ShareCount == 0)
                {
                    debugged = true;
                }
                break;
            }
        }
    }

    if (memory_pointer)
    {
        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &memory_pointer, &free_size, MEM_RELEASE);
    }

    return debugged;
}