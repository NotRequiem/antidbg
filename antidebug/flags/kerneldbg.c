#include "kerneldbg.h"
#include "..\core\syscall.h"

static inline bool _check_async(void)
{
    const ULONG_PTR user_shared_data = 0x7FFE0000;

    volatile const ULONG* interrupt_low = (volatile const ULONG*)(user_shared_data + 0x0008);
    volatile const ULONG* system_low = (volatile const ULONG*)(user_shared_data + 0x0014);
    volatile const ULONG* tick_low = (volatile const ULONG*)(user_shared_data + 0x0320);

    const ULONG initial_interrupt = *interrupt_low;
    const ULONG initial_system = *system_low;
    const ULONG initial_tick = *tick_low;

    unsigned __int64 start_tsc = __rdtsc();
    bool async_ticked = false;

    // kernel timer ISRs fire every 1 ms to 15.625 ms (64Hz) at default resolution
    for (volatile int i = 0; i < 40000000; ++i)
    {
        if (*interrupt_low != initial_interrupt ||
            *system_low != initial_system ||
            *tick_low != initial_tick)
        {
            async_ticked = true;
            break;
        }

        if ((i & 0x7FFFF) == 0)
        {
            if ((__rdtsc() - start_tsc) > 300000000ULL)
            {
                break;
            }
        }
    }

    return async_ticked;
}

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

    if (!_check_async())
    {
        return true;
    }

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
