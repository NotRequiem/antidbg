#include "hwbreakp.h"
#include "..\core\syscall.h"

bool HardwareBreakpoint(const HANDLE hThread)
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!DbgNtGetContextThread(hThread, &ctx))
        return false;

    return (ctx.Dr0 != 0) || (ctx.Dr1 != 0) || (ctx.Dr2 != 0) || (ctx.Dr3 != 0);
}