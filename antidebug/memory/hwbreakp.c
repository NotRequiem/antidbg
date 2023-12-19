#include "hwbreakp.h"

bool HardwareBreakpoint()
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;

    return (ctx.Dr0 != 0) || (ctx.Dr1 != 0) || (ctx.Dr2 != 0) || (ctx.Dr3 != 0);
}