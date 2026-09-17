#include "ice.h"
#include "..\core\syscall.h"

static inline bool _non_stealth()
{
    bool is_debugged = true;

    __try {
        RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, NULL);

        is_debugged = true;
    }
    __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        is_debugged = false;
    }

    return is_debugged;
}

const uint8_t _icebp_stub[] = { 0xF1, 0xC3 }; // icebp; ret

bool __adbg_ice(const HANDLE thread_handle)
{
    if (_non_stealth()) return true;

    bool debugged = true;
    HANDLE process_handle = (HANDLE)-1;
    PVOID exec_mem = NULL;
    SIZE_T region_size = sizeof(_icebp_stub);

    if (DbgNtAllocateVirtualMemory(process_handle, &exec_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0) {
        memcpy(exec_mem, _icebp_stub, sizeof(_icebp_stub));

        ULONG old_protect = 0;
        PVOID protect_base = exec_mem;
        SIZE_T protect_size = sizeof(_icebp_stub);

        if (DbgNtProtectVirtualMemory(process_handle, &protect_base, &protect_size, PAGE_EXECUTE_READ, &old_protect) >= 0) {
            DbgNtFlushInstructionCache(process_handle, exec_mem, sizeof(_icebp_stub));

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