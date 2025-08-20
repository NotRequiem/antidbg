#include "handler.h"

LONG CALLBACK VectoredDebuggerCheck(PEXCEPTION_POINTERS pExceptionInfo) {
    if (!pExceptionInfo || !pExceptionInfo->ContextRecord || !pExceptionInfo->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        PCONTEXT ctx = pExceptionInfo->ContextRecord;
        if (ctx->Dr0 || ctx->Dr1 || ctx->Dr2 || ctx->Dr3) {
            __fastfail(STATUS_FATAL_APP_EXIT);
        }
    }

    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));
    if (!hNtdll) return EXCEPTION_CONTINUE_SEARCH;

    FARPROC pKi = GetProcAddress(hNtdll, "KiUserExceptionDispatcher");
    if (!pKi) return EXCEPTION_CONTINUE_SEARCH;

    __try {
        BYTE first = *(BYTE*)pKi;
        if (first == 0xE9) {
            __fastfail(STATUS_CONTROL_STACK_VIOLATION);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return EXCEPTION_CONTINUE_SEARCH;
}
