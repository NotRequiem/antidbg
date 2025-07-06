#include "timing.h"

static BOOL CheckDebuggerTiming(void)
{
    const ULONGLONG time1 = GetTickCount64();

    // volatile so these stores actually happen and aren't optimized out
    volatile DWORD ecx = 10;
    volatile DWORD edx = 6;
    UNUSED(edx);
    ecx = 10;

    const ULONGLONG time2 = GetTickCount64();

    // assume we're single-stepped
    return (time2 - time1 > 0x1A) ? TRUE : FALSE;
}

bool TimingAttacks()
{
	ULONGLONG x = GetTickCount64(); 
    ULONGLONG y = GetTickCount64();

	if (x == y) return false;	

    x = GetTickCount64();
    Sleep(50);
    y = GetTickCount64();

    ULONGLONG elapsedTime = x - y;
    bool detection_value = elapsedTime > 100;
    if (detection_value) return true;

    static ULONGLONG time = 0;
    if (time == 0) {
        time = __rdtsc();
        return false;
    }
    ULONGLONG second_time = __rdtsc();
    ULONGLONG diff = (second_time - time) >> 20;
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

    SYSTEMTIME sysStart, sysend;
    FILETIME fStart, fEnd;
    ULARGE_INTEGER uiStart = { 0 }, uiEnd = { 0 };

    GetLocalTime(&sysStart);
    Sleep(50);
    GetLocalTime(&sysend);

    if (!SystemTimeToFileTime(&sysend, &fEnd))
        return false;
    if (!SystemTimeToFileTime(&sysStart, &fStart))
        return false;

    uiStart.LowPart = fStart.dwLowDateTime;
    uiStart.HighPart = fStart.dwHighDateTime;
    uiEnd.LowPart = fEnd.dwLowDateTime;
    uiEnd.HighPart = fEnd.dwHighDateTime;

    detection_value = (((uiEnd.QuadPart - uiStart.QuadPart) * 100) / 1000000) > 100;
    if (!detection_value) return CheckDebuggerTiming();
    else return true;
}