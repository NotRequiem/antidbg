#include "callback.h"
#include "syscall.h"

CALLBACK_PAGE g_callback_page = { 0 };

bool __set_callback(CALLBACK_PAGE* out_page, HANDLE process_handle)
{
    const uint8_t shellcode[] = { 0x41, 0xFF, 0xE2 }; // jmp r10

    PVOID new_base_address = NULL;
    SIZE_T region_size = 4096;
    ULONG old_protection = 0;
    SIZE_T bytes_written = 0;

    // new page as we will be running this infinitely, we must not overwrite the currently active callback page, as a thread might be actively executing the jmp r10 shellcode
    if (!NT_SUCCESS(DbgNtAllocateVirtualMemory(
        process_handle,
        &new_base_address,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE)))
        return false;

    if (!NT_SUCCESS(DbgNtWriteVirtualMemory(
        process_handle,
        new_base_address,
        (PVOID)shellcode,
        sizeof(shellcode),
        &bytes_written)))
        return false;

    if (!NT_SUCCESS(DbgNtProtectVirtualMemory(
        process_handle,
        &new_base_address,
        &region_size,
        PAGE_EXECUTE_READ,
        &old_protection)))
        return false;

    DbgNtFlushInstructionCache(process_handle, new_base_address, (ULONG)region_size);

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callback_info = { 0 };
    callback_info.Version = 0;
    callback_info.Reserved = 0;
    callback_info.Callback = new_base_address;

    if (!NT_SUCCESS(DbgNtSetInformationProcess(
        process_handle,
        ProcessInstrumentationCallback,
        &callback_info,
        sizeof(callback_info))))
        return false;

    if (out_page && out_page->base != NULL) {
        PVOID old_base = out_page->base;
        SIZE_T free_size = 0; 
        DbgNtFreeVirtualMemory(process_handle, &old_base, &free_size, MEM_RELEASE);
    }

    if (out_page) {
        out_page->base = new_base_address;
        out_page->size = region_size;
    }

    return true;
}

bool __detect_callback(PVOID callback_page, SIZE_T page_size, HANDLE process_handle)
{
    if (!callback_page || page_size < 3)
        return false;

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callback_info = { 0 };
    ULONG return_length = 0;

    const NTSTATUS status = DbgNtQueryInformationProcess(
        process_handle,
        ProcessInstrumentationCallback,
        &callback_info,
        sizeof(callback_info),
        &return_length
    );

    if (NT_SUCCESS(status))
    {
        if (callback_info.Callback != callback_page)
            return false;
    }
    else if (status != STATUS_INVALID_INFO_CLASS && status != STATUS_INFO_LENGTH_MISMATCH)
    {
        return false;
    }

    PVOID local_buffer = NULL;
    SIZE_T buffer_size = page_size;

    if (!NT_SUCCESS(DbgNtAllocateVirtualMemory((HANDLE)-1, &local_buffer, 0, &buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
        return false;

    SIZE_T bytes_read = 0;
    NTSTATUS read_status = DbgNtReadVirtualMemory(
        process_handle,
        callback_page,
        local_buffer,
        page_size,
        &bytes_read
    );

    bool is_intact = true;

    if (!NT_SUCCESS(read_status) || bytes_read < 3)
    {
        is_intact = false;
    }
    else
    {
        uint8_t* p_bytes = (uint8_t*)local_buffer;

        // shellcode
        if (p_bytes[0] != 0x41 || p_bytes[1] != 0xFF || p_bytes[2] != 0xE2)
        {
            is_intact = false;
        }
        else
        {
            // padding
            for (SIZE_T i = 3; i < page_size; i++)
            {
                if (p_bytes[i] != 0x00)
                {
                    is_intact = false;
                    break;
                }
            }
        }
    }

    SIZE_T free_size = 0;
    DbgNtFreeVirtualMemory((HANDLE)-1, &local_buffer, &free_size, MEM_RELEASE);

    return is_intact;
}