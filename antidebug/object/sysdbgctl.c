#include "sysdbgctl.h"
#include "..\core\syscall.h"

bool NtSystemDebugControl() 
{
    NTSTATUS status = DbgNtSystemDebugControl(
        20,      // SystemDebugControlCode::DebugPort
        NULL, 0, // in
        NULL, 0, // out
        NULL     // return length
    );

    const NTSTATUS STATUS_DEBUGGER_INACTIVE = 0xC0000354L;
    const NTSTATUS STATUS_ACCESS_DENIED = 0xC0000022L;

    if (status == STATUS_DEBUGGER_INACTIVE) {
        return FALSE;
    }
    else if (status == STATUS_ACCESS_DENIED) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}
