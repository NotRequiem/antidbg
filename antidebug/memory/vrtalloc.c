#include "vrtalloc.h"
#include "../core/syscall.h"

static inline bool _virtual_alloc_write_watch_buffer_only(const HANDLE process_handle)
{
    ULONG hit_count;
    ULONG granularity;
    bool result = false;

    PVOID addresses = NULL;
    SIZE_T addresses_size = 4096 * sizeof(ULONG);
    if (DbgNtAllocateVirtualMemory(process_handle, &addresses, 0, &addresses_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0) {
        return result;
    }

    SIZE_T buffer_size = (SIZE_T)4096 * (SIZE_T)4096;
    int* buffer = NULL;
    if (DbgNtAllocateVirtualMemory(process_handle, (PVOID*)&buffer, 0, &buffer_size, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE) < 0)
    {
        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &addresses, &free_size, MEM_RELEASE);
        return result;
    }

    buffer[0] = 1234;

    hit_count = 4096;
    if (DbgNtGetWriteWatch(process_handle, 0UL, (PVOID)buffer, (ULONG)buffer_size, (PULONG)addresses, &hit_count, &granularity) != 0)
    {
        result = false;
    }
    else
    {
        result = hit_count != 1;
    }

    SIZE_T free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, &addresses, &free_size, MEM_RELEASE);
    free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, (PVOID*)&buffer, &free_size, MEM_RELEASE);

    return result;
}

static inline bool _virtual_alloc_write_watch_api_calls(const HANDLE process_handle)
{
    ULONG hit_count;
    ULONG granularity;
    bool result = false, error = false;

    PVOID addresses = NULL;
    SIZE_T addresses_size = 4096 * sizeof(ULONG);
    if (DbgNtAllocateVirtualMemory(process_handle, &addresses, 0, &addresses_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0) {
        return result;
    }

    SIZE_T buffer_size = (SIZE_T)4096 * (SIZE_T)4096;
    int* buffer = NULL;
    if (DbgNtAllocateVirtualMemory(process_handle, (PVOID*)&buffer, 0, &buffer_size, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE) < 0)
    {
        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &addresses, &free_size, MEM_RELEASE);
        return result;
    }

    // make a bunch of calls where buffer *can* be written to, but isn't actually touched due to invalid parameters.
    // this can catch out API hooks whose return-by-parameter behaviour is different to that of regular APIs

    HANDLE invalid_handle = (HANDLE)(LONG_PTR)-2;

    if (DbgNtQueryInformationProcess(invalid_handle, 0, buffer, 4096, NULL) >= 0)
    {
        result = false;
        error = true;
    }
    if (DbgNtReadVirtualMemory(invalid_handle, (PVOID)(ULONG_PTR)0x69696969, buffer, 4096, NULL) >= 0)
    {
        result = false;
        error = true;
    }
    if (DbgNtGetContextThread(invalid_handle, (PCONTEXT)buffer) >= 0)
    {
        result = false;
        error = true;
    }
    if (DbgNtQueryInformationThread(invalid_handle, 0, buffer, 4096, NULL) >= 0)
    {
        result = false;
        error = true;
    }
    if (DbgNtGetWriteWatch(process_handle, 0UL, (PVOID)&_virtual_alloc_write_watch_api_calls, 0UL, NULL, &hit_count, &granularity) == 0)
    {
        result = false;
        error = true;
    }

    if (error == false)
    {
        hit_count = 4096;
        if (DbgNtGetWriteWatch(process_handle, 0UL, (PVOID)buffer, (ULONG)buffer_size, (PULONG)addresses, &hit_count, &granularity) != 0)
        {
            result = false;
        }
        else
        {
            result = hit_count != 0;
        }
    }

    SIZE_T free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, &addresses, &free_size, MEM_RELEASE);
    free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, (PVOID*)&buffer, &free_size, MEM_RELEASE);

    return result;
}

static inline bool _virtual_alloc_write_watch_is_debugger_present(const HANDLE process_handle)
{
    ULONG hit_count;
    ULONG granularity;
    bool result = false;

    PVOID addresses = NULL;
    SIZE_T addresses_size = 4096 * sizeof(ULONG);
    if (DbgNtAllocateVirtualMemory(process_handle, &addresses, 0, &addresses_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0) {
        return result;
    }

    SIZE_T buffer_size = (SIZE_T)4096 * (SIZE_T)4096;
    int* buffer = NULL;
    if (DbgNtAllocateVirtualMemory(process_handle, (PVOID*)&buffer, 0, &buffer_size, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE) < 0) {
        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &addresses, &free_size, MEM_RELEASE);
        return result;
    }

    buffer[0] = IsDebuggerPresent();

    hit_count = 4096;
    if (DbgNtGetWriteWatch(process_handle, 0UL, (PVOID)buffer, (ULONG)buffer_size, (PULONG)addresses, &hit_count, &granularity) != 0)
    {
        result = false;
    }
    else
    {
        result = (hit_count != 1) | (buffer[0] == TRUE);
    }

    SIZE_T free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, &addresses, &free_size, MEM_RELEASE);
    free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, (PVOID*)&buffer, &free_size, MEM_RELEASE);

    return result;
}

static inline bool _virtual_alloc_write_watch_code_write(const HANDLE process_handle)
{
    ULONG hit_count;
    ULONG granularity;
    bool result = false;

    PVOID addresses = NULL;
    SIZE_T addresses_size = 4096 * sizeof(ULONG);
    if (DbgNtAllocateVirtualMemory(process_handle, &addresses, 0, &addresses_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) < 0) {
        return result;
    }

    SIZE_T buffer_size = (SIZE_T)4096 * (SIZE_T)4096;
    unsigned char* buffer = NULL;
    if (DbgNtAllocateVirtualMemory(process_handle, (PVOID*)&buffer, 0, &buffer_size, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_EXECUTE_READWRITE) < 0) {
        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &addresses, &free_size, MEM_RELEASE);
        return result;
    }

    ULONG_PTR is_debugger_present_addr = (ULONG_PTR)&IsDebuggerPresent;

    /*
     * 64-bit
     *
        0:  51                              push   rcx
        1:  48 b9 ef cd ab 90 78 56 34 12   movabs rcx, 0x1234567890abcdef
        b:  ff d1                           call   rcx
        d:  59                              pop    rcx
        e:  c3                              ret
     */
    int pos = 0;
    buffer[pos++] = 0x51;
    buffer[pos++] = 0x48;
    buffer[pos++] = 0xB9;
    int offset = 0;
    for (int n = 0; n < 8; n++)
    {
        buffer[pos++] = (unsigned char)((is_debugger_present_addr >> offset) & 0xFF);
        offset += 8;
    }
    buffer[pos++] = 0xFF;
    buffer[pos++] = 0xD1;
    buffer[pos++] = 0x59;
    buffer[pos] = 0xC3;

    DbgNtResetWriteWatch(process_handle, (PVOID)buffer, (ULONG)buffer_size);

    BOOL(*foo)(VOID) = (BOOL(*)(VOID))buffer;
    if (foo() == TRUE)
    {
        result = true;
    }

    if (result == false)
    {
        hit_count = 4096;
        if (DbgNtGetWriteWatch(process_handle, 0UL, (PVOID)buffer, (ULONG)buffer_size, (PULONG)addresses, &hit_count, &granularity) != 0)
        {
            result = false;
        }
        else
        {
            result = hit_count != 0;
        }
    }

    SIZE_T free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, &addresses, &free_size, MEM_RELEASE);
    free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, (PVOID*)&buffer, &free_size, MEM_RELEASE);

    return result;
}

bool __adbg_write_watch(const HANDLE process_handle)
{
    if (_virtual_alloc_write_watch_buffer_only(process_handle))
        return true;
    if (_virtual_alloc_write_watch_api_calls(process_handle))
        return true;
    if (_virtual_alloc_write_watch_is_debugger_present(process_handle))
        return true;
    if (_virtual_alloc_write_watch_code_write(process_handle))
        return true;

    return false;
}