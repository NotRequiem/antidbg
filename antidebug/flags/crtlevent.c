#include "crtlevent.h"

static volatile LONG g_debugged = 0;
static volatile LONG g_crtlc_catched = 0;

static LONG __stdcall _ctrl_event_exception_handler(PEXCEPTION_POINTERS exception_info)
{
    if (exception_info &&
        exception_info->ExceptionRecord &&
        exception_info->ExceptionRecord->ExceptionCode == DBG_CONTROL_C)
    {
        _InterlockedExchange(&g_debugged, 1);
        _InterlockedExchange(&g_crtlc_catched, 1);
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

static BOOL __stdcall _ctrl_handler(DWORD fdw_ctrl_type)
{
    switch (fdw_ctrl_type)
    {
    case CTRL_C_EVENT:
        _InterlockedExchange(&g_crtlc_catched, 1);
        return TRUE;
    default:
        return FALSE;
    }
}

bool __adbg_console_event()
{
    PVOID veh = NULL;
    BOOL ctrl_handler_set = FALSE;

    __try
    {
        veh = AddVectoredExceptionHandler(1, _ctrl_event_exception_handler);
        if (!veh)
            __leave;

        ctrl_handler_set = SetConsoleCtrlHandler(_ctrl_handler, TRUE);
        if (!ctrl_handler_set)
            __leave;

        _InterlockedExchange(&g_crtlc_catched, 0);
        _InterlockedExchange(&g_debugged, 0);

        GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);

        while (_InterlockedCompareExchange(&g_crtlc_catched, 0, 0) == 0)
        {
            SleepEx(0, FALSE);
        }
    }
    __finally
    {
        if (ctrl_handler_set)
            SetConsoleCtrlHandler(_ctrl_handler, FALSE);

        if (veh)
            RemoveVectoredExceptionHandler(veh);
    }

    return _InterlockedCompareExchange(&g_debugged, 0, 0) != 0;
}