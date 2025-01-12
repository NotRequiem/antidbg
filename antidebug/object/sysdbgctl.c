#include "sysdbgctl.h"
#include "..\core\syscall.h"


bool NtSystemDebugControl() {
    NTSTATUS status = DbgNtSystemDebugControl(20, NULL, 0, NULL, 0, NULL);

    const NTSTATUS STATUS_DEBUGGER_INACTIVE = 0xC0000354L;
    const NTSTATUS STATUS_ACCESS_DENIED = 0xC0000022L;

    if (status == STATUS_DEBUGGER_INACTIVE) {
        return FALSE;
    }
    else {
        if (status != STATUS_ACCESS_DENIED) {}
        return TRUE;
    }
}
