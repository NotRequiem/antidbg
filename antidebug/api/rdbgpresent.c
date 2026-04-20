#include "rdbgpresent.h"

bool __adbg_remote_debugger(const HANDLE process_handle)
{
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(process_handle, &debugged);
    return debugged;
}