#include "suspend.h"
#include "..\core\syscall.h"
#include "..\core\thrmng.h"

DWORD __stdcall _dummy(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    LARGE_INTEGER delay = { 0 };
    delay.QuadPart = -100000000LL;

    while (true) {
        DbgNtDelayExecution(FALSE, &delay);
    }
    return 0;
}

DWORD __stdcall _suspend_thread(LPVOID lpParam)
{
    HANDLE target_thread = (HANDLE)lpParam;
    NTSTATUS status;
    ULONG previous_suspend_count;

    for (int i = 0; i < MAX_SUSPEND_COUNT + 5; i++) {
        DbgNtSuspendThread(target_thread, &previous_suspend_count);
    }

    LARGE_INTEGER sleep_interval = { 0 };
    sleep_interval.QuadPart = -20000000LL;

    while (true) {
        status = DbgNtSuspendThread(target_thread, &previous_suspend_count);

        // if a debugger or tool called NtResumeProcess, the target thread's suspend count 
        // will have decremented so our call above will return STATUS_SUCCESS instead of throwing the expected exceeded error
        if (status != STATUS_SUSPEND_COUNT_EXCEEDED)
        {
            const HANDLE current_process = (HANDLE)(-1LL);
            DbgNtTerminateProcess(current_process, 0);
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }

        DbgNtDelayExecution(FALSE, &sleep_interval);
    }

    return 0;
}

bool __adbg_suspension(const HANDLE process_handle)
{
    static bool init = false;
    if (init) return false;
    
    HANDLE thread1 = NULL; // monitor thread
    HANDLE thread2 = NULL; // target thread

    thread2 = DbgCreateThread(process_handle, 0, _dummy, NULL, THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE, NULL, NULL);
    if (!thread2) return false;

    thread1 = DbgCreateThread(process_handle, 0, _suspend_thread, thread2, THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE, NULL, NULL);
    if (!thread1)
    {
        DbgNtClose(thread2);
        return false;
    }

    // monitor thread requires the handle to hThread2 to remain valid indefinitely to keep suspending it
    // DbgNtClose(hThread1);
    // DbgNtClose(hThread2);

    init = true;
    return false;
}