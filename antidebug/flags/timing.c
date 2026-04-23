#include "timing.h"

static inline bool _time_debugger(void)
{
    const ULONGLONG time1 = GetTickCount64();

    volatile DWORD ecx = 10;
    volatile DWORD edx = 6;
    UNUSED(edx);
    UNUSED(ecx);
    ecx = 10;

    const ULONGLONG time2 = GetTickCount64();

    return (time2 - time1 > 0x1A) ? true : false;
}

static inline bool _time_single_step(void)
{
    for (int i = 0; i < 10; i++)
    {
        uint64_t tsc1, tsc2;
        int cpu_info[4];

        __cpuid(cpu_info, 0); // just for serialization, a hypervisor wouldn't affect this measure
        tsc1 = __rdtsc();

        volatile int a = 0;
        for (int j = 0; j < 100; j++) {
            a += j;
        }

        tsc2 = __rdtsc();
        __cpuid(cpu_info, 0);

        // 0xFFFFF is 1 million cycles aprox
        if ((tsc2 - tsc1) < 0xFFFFF) {
            return false; 
        }
    }

    return true;
}

bool __adbg_timing_attack()
{
    bool is_debugged = false;
    if (_time_single_step()) {
        is_debugged = true;
    }

    if (!is_debugged) return _time_debugger();
    
    return is_debugged;
}