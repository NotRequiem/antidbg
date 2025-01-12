#include "dbgpresent.h"

bool IsBeingDebugged()
{
    return IsDebuggerPresent() == TRUE;
}
