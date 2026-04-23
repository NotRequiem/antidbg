#include "popf.h"

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

#if defined(_MSC_VER) && !defined(__clang__)

    #pragma section(".__stub", execute, read)

    __declspec(allocate(".__stub")) const uint8_t _popf_stub[] = {
        0x9C, 0x48, 0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, 0x9D, 0x90, 0xC3
    }; // pushfq; or qword ptr [rsp], 0x100; popfq; nop; ret

    #define __trap(shellcode) \
        bool debugged = true; \
        __try { \
            ((void(*)())shellcode)(); \
        } __except(EXCEPTION_EXECUTE_HANDLER) { \
            debugged = false; \
        } \
        return debugged;

    bool __adbg_popf()
    {
        if (_non_stealth()) return true;
        __trap(_popf_stub);
    }

#else

    _Thread_local volatile bool g_exception_fired = false;

    static LONG __stdcall _excp_handler(PEXCEPTION_POINTERS ep)
    {
        DWORD code = ep->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT)
        {
            g_exception_fired = true;

            // clear TF and DR6 so we don't infinitely single-step
            ep->ContextRecord->EFlags &= ~0x100;
            ep->ContextRecord->Dr6 &= ~(0xF);

            // for POPF (single step), RIP automatically points to the next instruction
            // so this should be safe
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

    static void _asm_popf() {
        __asm__ __volatile__(
            "pushfq \n\t"
            "orq $0x100, (%%rsp) \n\t" // set TF (bit 8)
            "popfq \n\t"
            "nop \n\t"                 // trap triggers here
            : : : "cc", "memory"
        );
    }

    bool __adbg_popf()
    {
        if (_non_stealth()) return true;
        return __trap(_asm_popf);
    }

#endif