#include "sckreg.h"

bool StackSegmentRegister()
{
    bool bTraced = false;

    __try
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;

        // Get the current thread context
        GetThreadContext(GetCurrentThread(), &ctx);

        // Manipulate the context to simulate the assembly instructions
        ctx.SegGs = ctx.SegSs;
        ctx.EFlags |= 0x100; // Set the Trap Flag (TF)

        // Set the modified context
        SetThreadContext(GetCurrentThread(), &ctx);

        // Trigger a single-step exception
        RaiseException(EXCEPTION_SINGLE_STEP, EXCEPTION_NONCONTINUABLE, 0, NULL);

        // If the code reaches here, it means the Trap Flag was not cleared
        bTraced = true;
    }
    __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        // Exception handling for single-step exception
    }

    return bTraced;
}