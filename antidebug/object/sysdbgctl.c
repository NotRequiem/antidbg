#include "sysdbgctl.h"

bool NtSystemDebugControl() {
    PFN_NtSystemDebugControl NtSystemDebugControl_ = GetNtSystemDebugControlPointer();
    if (NtSystemDebugControl_ == NULL) {
        printf("Failed to get pointer for NtSystemDebugControl\n");
        return FALSE;
    }

    NTSTATUS status = NtSystemDebugControl_(20, NULL, 0, NULL, 0, NULL);

    const NTSTATUS STATUS_DEBUGGER_INACTIVE = 0xC0000354L;
    const NTSTATUS STATUS_ACCESS_DENIED = 0xC0000022L;

    if (status == STATUS_DEBUGGER_INACTIVE) {
        return FALSE;
    }
    else {
        if (status != STATUS_ACCESS_DENIED) {
        }
        return TRUE;
    }
}
