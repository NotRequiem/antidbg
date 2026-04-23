#include "kerneldbg.h"
#include "..\core\syscall.h"

static inline bool __read_kuser_shared_data()
{
    const ULONG_PTR user_shared_data = 0x7FFE0000;

    const UCHAR kd_debugger_enabled_byte = *(UCHAR*)(user_shared_data + 0x2D4);

    const BOOLEAN kd_debugger_enabled = (kd_debugger_enabled_byte & 0x1) == 0x1;
    const BOOLEAN kd_debugger_not_present = (kd_debugger_enabled_byte & 0x2) == 0;

    /*
    * const unsigned char b = *(unsigned char*)0x7ffe02d4; 
    * if ((b & 0x03) != 0)
    *    return true;
    */

    if (kd_debugger_enabled || !kd_debugger_not_present)
        return true;

    return false;
}

bool __adbg_kernel_debugger() 
{
    const bool result = __read_kuser_shared_data();

    if (result) {
        return true;
    }

    SYSTEM_KERNEL_DEBUGGER_INFORMATION system_info = { 0 };

    const NTSTATUS status = DbgNtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
        &system_info,
        sizeof(system_info),
        NULL);

    return (((NTSTATUS)(status)) >= 0)
        ? (system_info.DebuggerEnabled && !system_info.DebuggerNotPresent)
        : false;
}
