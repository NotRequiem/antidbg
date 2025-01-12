#include "sckreg.h"

bool StackSegmentRegister(const HANDLE hThread)
{
    bool bTraced = false;
    CONTEXT context = { 0 };

    context.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&context);

    context.EFlags |= 0x100;

    if (SetThreadContext(hThread, &context)) // do not syscall
    {
        __try
        {
            RaiseException(EXCEPTION_SINGLE_STEP, 0, 0, NULL);
        }
        __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
            ? EXCEPTION_EXECUTE_HANDLER
            : EXCEPTION_CONTINUE_SEARCH)
        {
            bTraced = true;
        }
    }

    return bTraced;
}