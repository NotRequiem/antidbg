// In Development

#include <windows.h>
#include <stdbool.h>

LONG UnhandledExceptionFilterr(PEXCEPTION_POINTERS pExceptionInfo)
{
    PCONTEXT ctx = pExceptionInfo->ContextRecord;
    ctx->Eip += 3; // Skip \xCC\xEB\x??
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool Check()
{
    bool bDebugged = true;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)UnhandledExceptionFilter);

    __try
    {
        __asm int 3;                     // CC
        __asm jmp near being_debugged;   // EB ??
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        bDebugged = false;
    }

being_debugged:
    return bDebugged;
}

int main()
{
    if (Check()) {
        MessageBoxA(HWND_DESKTOP, "Not Debugged", "", MB_OK);
    }
    else {
        MessageBoxA(HWND_DESKTOP, "Debugged", "", MB_OK);
    }

    ExitProcess(0);
    return 0;
}
