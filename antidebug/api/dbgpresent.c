#include "dbgpresent.h"

bool __adbg_is_debugger_present()
{
    return IsDebuggerPresent() == TRUE; // inline hooks for this call are performed in monitor.c
}
