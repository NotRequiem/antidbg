#include "sckreg.h"

bool StackSegmentRegister(const HANDLE hThread)
{
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);

    DWORD origEFlags = ctx.EFlags;

    ctx.EFlags |= 0x100;
    if (!SetThreadContext(hThread, &ctx))
        return false;

    bool bTraced = false;
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
        bTraced = true;
    }

    result = bTraced;

cleanup:
    ctx.ContextFlags = CONTEXT_CONTROL;
    ctx.EFlags = origEFlags;
    SetThreadContext(hThread, &ctx);

    return result;
}