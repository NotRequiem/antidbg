#include "kerneldbg.h"

bool KernelDebugger() {
    NTSTATUS status;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInfo;

    status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
        &SystemInfo,
        sizeof(SystemInfo),
        NULL);

    return NT_SUCCESS(status)
        ? (SystemInfo.DebuggerEnabled && !SystemInfo.DebuggerNotPresent)
        : false;
}