#include "ice.h"

static inline bool _non_stealth(const HANDLE thread_handle) 
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);

    DWORD original_eflags = ctx.EFlags;

    ctx.EFlags |= 0x100;
    if (!SetThreadContext(thread_handle, &ctx))
        return false;

    bool traced = false;
    bool result = false;

    __try {
        RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, NULL);

        __try {
            RaiseException(0xF1, 0, 0, NULL);
        }
        __except (1) {
            result = false;
            goto cleanup;
        }

        result = true;
        goto cleanup;
    }
    __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        traced = true;
    }

    result = traced;

cleanup:
    ctx.ContextFlags = CONTEXT_CONTROL;
    ctx.EFlags = original_eflags;
    SetThreadContext(thread_handle, &ctx);

    return result;
}

#if defined(_MSC_VER) && !defined(__clang__)

#define __trap(shellcode) \
    bool debugged = true; \
    __try { \
        ((void(*)())shellcode)(); \
    } __except(EXCEPTION_EXECUTE_HANDLER) { \
        debugged = false; \
    } \
    return debugged;

    #pragma section(".__stub", execute, read)

    __declspec(allocate(".__stub")) const uint8_t _icebp_stub[] = {
        0xF1, 0xC3
    }; // int 1; ret

    bool __adbg_ice(const HANDLE thread_handle) 
    {
        if (_non_stealth(thread_handle)) return true;
        __trap(_icebp_stub);
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

            // for INT 1, RIP automatically points to the next instruction
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

    static void _asm_icebp() { __asm__ __volatile__("int $1 \n\t"); }

    bool __adbg_ice(const HANDLE thread_handle) { 
        if (_non_stealth(thread_handle)) return true;
        return __trap(_asm_icebp);
    }

#endif