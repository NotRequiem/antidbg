#include "prehop.h"
#include "..\core\syscall.h"

bool __adbg_prefix_hop()
{
    bool found = true;
    const unsigned char code[] = {
            0xF3, // REP prefix
            0x64, // FS prefix
            0xF1  // software bp
    };

    HANDLE process_handle = (HANDLE)-1;
    PVOID exec_mem = NULL;
    SIZE_T region_size = sizeof(code);

    if (DbgNtAllocateVirtualMemory(process_handle, &exec_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0) {
        memcpy(exec_mem, code, sizeof(code));

        ULONG old_protect = 0;
        PVOID protect_base = exec_mem;
        SIZE_T protect_size = sizeof(code);

        if (DbgNtProtectVirtualMemory(process_handle, &protect_base, &protect_size, PAGE_EXECUTE_READ, &old_protect) >= 0) {
            DbgNtFlushInstructionCache(process_handle, exec_mem, sizeof(code));

            __try {
                ((void(*)())exec_mem)();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                found = false;
            }
        }

        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &exec_mem, &free_size, MEM_RELEASE);
    }

    return found;
}