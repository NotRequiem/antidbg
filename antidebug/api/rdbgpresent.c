#include "rdbgpresent.h"

bool IsRemoteDebuggerPresent(const HANDLE hProcess)
{
    BOOL isRemoteDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(hProcess, &isRemoteDebuggerPresent);
    return isRemoteDebuggerPresent;
}