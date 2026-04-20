#include "timing.h"

static bool _time_debugger(void)
{
    const ULONGLONG time1 = GetTickCount64();

    // volatile so these stores actually happen and aren't optimized out
    volatile DWORD ecx = 10;
    volatile DWORD edx = 6;
    UNUSED(edx);
    ecx = 10;

    const ULONGLONG time2 = GetTickCount64();

    // assume we're single-stepped
    return (time2 - time1 > 0x1A) ? true : false;
}

bool __adbg_timing_attack()
{
	ULONGLONG x = GetTickCount64(); 
    ULONGLONG y = GetTickCount64();

	if (x == y) return false;	

    x = GetTickCount64();
    Sleep(50);
    y = GetTickCount64();

    const ULONGLONG elapsedTime = x - y;
    bool detection_value = elapsedTime > 100;
    if (detection_value) return true;

    static ULONGLONG time = 0;
    if (time == 0) {
        time = __rdtsc();
        return false;
    }
    const ULONGLONG second_time = __rdtsc();
    const ULONGLONG diff = (second_time - time) >> 20;
    if (diff > 0x100) {
        time = second_time;
        return true;
    }

    LARGE_INTEGER start, end, frequency;
    QueryPerformanceCounter(&start);
    QueryPerformanceFrequency(&frequency);

    SleepEx(50, FALSE);

    QueryPerformanceCounter(&end);

    detection_value = (end.QuadPart - start.QuadPart) * 1000 / frequency.QuadPart > 100;
    if (detection_value) return true;

    SYSTEMTIME sys_start, sysend;
    FILETIME fstart, fend;
    ULARGE_INTEGER uistart = { 0 }, uiend = { 0 };

    GetLocalTime(&sys_start);
    Sleep(50);
    GetLocalTime(&sysend);

    if (!SystemTimeToFileTime(&sysend, &fend))
        return false;
    if (!SystemTimeToFileTime(&sys_start, &fstart))
        return false;

    uistart.LowPart = fstart.dwLowDateTime;
    uistart.HighPart = fstart.dwHighDateTime;
    uiend.LowPart = fend.dwLowDateTime;
    uiend.HighPart = fend.dwHighDateTime;

    detection_value = (((uiend.QuadPart - uistart.QuadPart) * 100) / 1000000) > 100;
    if (!detection_value) return _time_debugger();
    else return true;
}