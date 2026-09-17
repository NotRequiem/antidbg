#include "int2d.h"
#include "..\core\syscall.h"

static inline bool _non_stealth() {
    __try
    {
        RaiseException(0x80000003, 0, 0, NULL);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        __try
        {
            RaiseException(0x2D, 0, 0, NULL);
        }
        __except (1)
        {
            return false;
        }
        return true;
    }
}

const uint8_t _int2d_stub[] = {
    0xCD, 0x2D, // int 2d
    0x90, 0x90, 0x90, 0x90, 0x90, // NOP sled
    0xC3 // ret 
};

bool __adbg_int2d()
{
    if (_non_stealth()) return true;

    bool debugged = true;
    HANDLE process_handle = (HANDLE)-1;
    PVOID exec_mem = NULL;
    SIZE_T region_size = sizeof(_int2d_stub);

    if (DbgNtAllocateVirtualMemory(process_handle, &exec_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0) {
        memcpy(exec_mem, _int2d_stub, sizeof(_int2d_stub));

        ULONG old_protect = 0;
        PVOID protect_base = exec_mem;
        SIZE_T protect_size = sizeof(_int2d_stub);

        if (DbgNtProtectVirtualMemory(process_handle, &protect_base, &protect_size, PAGE_EXECUTE_READ, &old_protect) >= 0) {
            DbgNtFlushInstructionCache(process_handle, exec_mem, sizeof(_int2d_stub));

            __try {
                ((void(*)())exec_mem)();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                debugged = false;
            }
        }

        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &exec_mem, &free_size, MEM_RELEASE);
    }
    return debugged;
}