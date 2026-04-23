#include "heap.h"
#include "..\core\syscall.h"

static _force_inline HANDLE __readheap()
{
    const PBYTE pPeb = (PBYTE)__readgsqword(0x60);
    return *(HANDLE*)(pPeb + 0x30);
}

static _force_inline bool _read_dword(const void* address, DWORD* out_val, const HANDLE process_handle)
{
    SIZE_T bytes_read = 0;
    NTSTATUS status = DbgNtReadVirtualMemory(
        process_handle,
        (PVOID)address,
        out_val,
        sizeof(DWORD),
        &bytes_read
    );

    return NT_SUCCESS(status) && (bytes_read == sizeof(DWORD));
}

bool __adbg_heap_magic(const HANDLE process_handle)
{
    void* ptr1 = HeapAlloc(__readheap(), 0, 32);
    void* ptr2 = HeapAlloc(__readheap(), 0, 32);
    if (ptr1) HeapFree(__readheap(), 0, ptr1);

    bool debugged = false;
    HANDLE heap_handle = __readheap();
    PROCESS_HEAP_ENTRY heap_entry = { 0 };

    // lock heap to prevent other threads from modifying it while we walk
    if (!HeapLock(heap_handle)) {
        return false;
    }

    while (HeapWalk(heap_handle, &heap_entry))
    {
        DWORD val = 0;

        // HEAP_TAIL_CHECKING_ENABLED (0xABABABAB)
        // if the block is allocated
        if (heap_entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
        {
            const PVOID overlapped = (PBYTE)heap_entry.lpData + heap_entry.cbData;

            if (heap_entry.cbData > 0)
            {
                if (_read_dword(overlapped, &val, process_handle) && val == 0xABABABAB)
                {
                    debugged = true;
                    break;
                }
            }
        }
        // HEAP_FREE_CHECKING_ENABLED (0xFEEEFEEE)
        // if the block is unallocated
        else
        {
            const PVOID data_pointer = heap_entry.lpData;

            if (heap_entry.cbData >= sizeof(DWORD))
            {
                if (_read_dword(data_pointer, &val, process_handle) && val == 0xFEEEFEEE)
                {
                    debugged = true;
                    break;
                }
            }
        }
    }

    HeapUnlock(heap_handle);
    if (ptr2) HeapFree(__readheap(), 0, ptr2);

    return debugged;
}