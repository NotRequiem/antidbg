#include "stckseg.h"
#include "..\core\syscall.h"

bool __adbg_ssr(const HANDLE process_handle)
{
    /*
        66 8C D0 mov ax, ss
        66 8E D0 mov ss, ax ; triggers 1-instruction interrupt shadow
        9C pushfq ; pushes RFLAGS (including TF)
        58 pop rax ; pop RFLAGS into RAX
        48 C1 E8 08 shr rax, 8 ; shift right 8 bits (trap flag is bit 8)
        48 83 E0 01 and rax, 1 ; mask out everything except the trap flag
        C3 ret ; ret
    */
    const uint8_t shellcode[] = {
        0x66, 0x8C, 0xD0,
        0x66, 0x8E, 0xD0,
        0x9C,
        0x58,
        0x48, 0xC1, 0xE8, 0x08,
        0x48, 0x83, 0xE0, 0x01,
        0xC3
    };

    PVOID exec_mem = NULL;
    SIZE_T region_size = sizeof(shellcode);

    if (DbgNtAllocateVirtualMemory(
        process_handle,
        &exec_mem,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    ) < 0)
    {
        return false;
    }

    memcpy(exec_mem, shellcode, sizeof(shellcode));

    ULONG old_protect = 0;
    PVOID protect_base = exec_mem;
    SIZE_T protect_size = sizeof(shellcode);

    if (DbgNtProtectVirtualMemory(
        process_handle,
        &protect_base,
        &protect_size,
        PAGE_EXECUTE_READ,
        &old_protect
    ) < 0)
    {
        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(
            process_handle,
            &exec_mem,
            &free_size,
            MEM_RELEASE
        );

        return false;
    }

    DbgNtFlushInstructionCache(
        process_handle,
        exec_mem,
        sizeof(shellcode)
    );

    typedef bool(*is_debugged_func)();
    bool debugged = false;

    __try {
        debugged = ((is_debugged_func)exec_mem)();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        debugged = true;
    }

    SIZE_T free_size = 0;
    DbgNtFreeVirtualMemory(
        process_handle,
        &exec_mem,
        &free_size,
        MEM_RELEASE
    );

    return debugged;
}