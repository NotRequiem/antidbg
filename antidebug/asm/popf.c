#include "popf.h"
#include "..\core\syscall.h"

static inline bool _non_stealth() {
    __try
    {
        RaiseException(EXCEPTION_TRAP_FLAG, 0, 0, NULL);
        return true;
    }
    __except (GetExceptionCode() == EXCEPTION_TRAP_FLAG
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_EXECUTION)
    {
        return false;
    }
}

const uint8_t _popf_stub[] = { 0x9C, 0x48, 0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, 0x9D, 0x90, 0xC3 };

bool __adbg_popf()
{
    if (_non_stealth()) return true;

    bool debugged = true;
    HANDLE process_handle = (HANDLE)-1;
    PVOID exec_mem = NULL;
    SIZE_T region_size = sizeof(_popf_stub);

    if (DbgNtAllocateVirtualMemory(process_handle, &exec_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0) {
        memcpy(exec_mem, _popf_stub, sizeof(_popf_stub));

        ULONG old_protect = 0;
        PVOID protect_base = exec_mem;
        SIZE_T protect_size = sizeof(_popf_stub);

        if (DbgNtProtectVirtualMemory(process_handle, &protect_base, &protect_size, PAGE_EXECUTE_READ, &old_protect) >= 0) {
            DbgNtFlushInstructionCache(process_handle, exec_mem, sizeof(_popf_stub));

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