#include "int3.h"

static volatile bool swallowed_exception = true;

static LONG __stdcall _vectored_handler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        swallowed_exception = false;
        ExceptionInfo->ContextRecord->Rip++; 
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

bool __adbg_int3()
{
    /* Since our program patches DbgBreakPoint, we can't use this
    DebugBreak();

    if (swallowed_exception) {
        RemoveVectoredExceptionHandler(veh);
        return swallowed_exception;
    }
    */
    // swallowed_exception = true;
    // DebugBreakProcess(process_handle);
    swallowed_exception = true;
    const PVOID veh = AddVectoredExceptionHandler(1, _vectored_handler);

    __debugbreak();

    if (swallowed_exception) {
        RemoveVectoredExceptionHandler(veh);
        return true;
    }

    RemoveVectoredExceptionHandler(veh);
    return false;
}