#include "rdbgpresent.h"

bool IsRemoteDebuggerPresent()
{
    HANDLE hProcess = GetCurrentProcess();
    BOOL isRemoteDebuggerPresent = FALSE;

    if (CheckRemoteDebuggerPresent(hProcess, &isRemoteDebuggerPresent) == TRUE)
    {
        return isRemoteDebuggerPresent == TRUE;
    }

    return true;
}