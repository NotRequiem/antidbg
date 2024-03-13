#include "hwbreakp2.h"

bool HardwareBreakPoint2()
{
    BOOL bResult = FALSE;

    PCONTEXT ctx = (PCONTEXT)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);

    if (ctx) {

        SecureZeroMemory(ctx, sizeof(CONTEXT));

        ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (GetThreadContext(GetCurrentThread(), ctx)) {

            if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
                bResult = TRUE;
        }

        VirtualFree(ctx, 0, MEM_RELEASE);
    }

    return bResult;
}
