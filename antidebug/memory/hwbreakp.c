#include "hwbreakp.h"
#include "..\core\syscall.h"

bool __adbg_hardware_breakpoint(const HANDLE thread_handle)
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!DbgNtGetContextThread(thread_handle, &ctx))
        return false;

    return (ctx.Dr0 != 0) || (ctx.Dr1 != 0) || (ctx.Dr2 != 0) || (ctx.Dr3 != 0);
}