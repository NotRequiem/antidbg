#include "int2d.h"

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

#if defined(_MSC_VER) && !defined(__clang__)

    #pragma section(".__stub", execute, read)

    __declspec(allocate(".__stub")) const uint8_t _int2d_stub[] = {
        0xCD, 0x2D, 0x90, 0xC3
    }; // int 0x2d; nop; ret

#define __trap(shellcode) \
    bool debugged = true; \
    __try { \
        ((void(*)())shellcode)(); \
    } __except(EXCEPTION_EXECUTE_HANDLER) { \
        debugged = false; \
    } \
    return debugged;

    bool __adbg_int2d() {
        if (_non_stealth()) return true;
        __trap(_int2d_stub);
    }

#else

    thread_local volatile bool g_exception_fired = false;

    static LONG __stdcall _excp_handler(PEXCEPTION_POINTERS ep)
    {
        DWORD code = ep->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT)
        {
            g_exception_fired = true;

            // clear TF and DR6 so we don't infinitely single-step
            ep->ContextRecord->EFlags &= ~0x100;
            ep->ContextRecord->Dr6 &= ~(0xF);

            // windows advances RIP automatically for INT 2D so this should be safe
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    static inline bool __trap(void (*_trap_func)())
    {
        g_exception_fired = false;
        PVOID veh = AddVectoredExceptionHandler(1, _excp_handler);
        if (!veh) return true;

        _trap_func();

        RemoveVectoredExceptionHandler(veh);

        return !g_exception_fired;
    }

    static void _asm_int2d() { __asm__ __volatile__("int $0x2D \n\tnop \n\t"); }

    bool __adbg_int2d()
    {
        if (_non_stealth()) return true;
        __trap(_asm_int2d);
    }

#endif