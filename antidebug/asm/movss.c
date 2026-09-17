#include "movss.h"
#include "..\core\syscall.h"

const uint8_t _movss_stub[] = {
    0x66, 0x8C, 0xD0, 0x66, 0x8E, 0xD0, 0x9C, 0x58, 0x48, 0xC1, 0xE8, 0x08, 0x48, 0x83, 0xE0, 0x01, 0xC3
}; // mov ax, ss; mov ss, ax; pushfq; pop rax; shr rax, 8; and rax, 1; ret

bool __adbg_mov_ss()
{
    bool debugged = false;
    HANDLE process_handle = (HANDLE)-1;
    PVOID exec_mem = NULL;
    SIZE_T region_size = sizeof(_movss_stub);

    if (DbgNtAllocateVirtualMemory(process_handle, &exec_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0) {
        memcpy(exec_mem, _movss_stub, sizeof(_movss_stub));

        ULONG old_protect = 0;
        PVOID protect_base = exec_mem;
        SIZE_T protect_size = sizeof(_movss_stub);

        if (DbgNtProtectVirtualMemory(process_handle, &protect_base, &protect_size, PAGE_EXECUTE_READ, &old_protect) >= 0) {
            DbgNtFlushInstructionCache(process_handle, exec_mem, sizeof(_movss_stub));

            typedef bool(*_movss_func)();
            debugged = ((_movss_func)exec_mem)();
        }

        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &exec_mem, &free_size, MEM_RELEASE);
    }
    return debugged;
}