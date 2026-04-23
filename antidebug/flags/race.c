#include "race.h"
#include "..\core\syscall.h"
#include "..\core\thrmng.h"

static void _dummy(void)
{
    volatile int x = 0;
    (void)x;
}

static inline bool _read_context_strip(const HANDLE thread_handle)
{
    const DWORD64 dummy_breakpoint = (DWORD64)(ULONG_PTR)&_dummy;

    _Alignas(16) CONTEXT ctx = { 0 };
    ctx.Dr0 = dummy_breakpoint;
    ctx.Dr7 = 1; // local DR0 execution breakpoint
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!NT_SUCCESS(DbgNtSetContextThread(thread_handle, &ctx)))
        return false;

    // clear so we can verify if the kernel actually saved it
    ctx.Dr0 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // read context back
    if (!NT_SUCCESS(DbgNtGetContextThread(thread_handle, &ctx)))
        return false;

    // remove the dummy breakpoint so we don't accidentally trigger it later
    _Alignas(16) CONTEXT cleanup_context = { 0 };
    cleanup_context.Dr0 = 0;
    cleanup_context.Dr7 = 0;
    cleanup_context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    DbgNtSetContextThread(thread_handle, &cleanup_context);

    // if Dr0 is not what we set, some debugger stripped the CONTEXT_DEBUG_REGISTERS flag
    if (ctx.Dr0 != dummy_breakpoint)
        return true;

    return false;
}

// thread that continuously hammers the ContextFlags to un-strip the 0x10 bit
DWORD __stdcall __race(LPVOID lpParam)
{
    RaceContext* rc = (RaceContext*)lpParam;

    while (rc->Run)
    {
        // DEBUG_REGISTERS flag
        // races against a debugger reading the struct and the kernel reading the struct
        rc->ContextPtr->ContextFlags |= 0x10;
    }

    return 0;
}

// function that forces hardware breakpoints through debuggers via race condition
bool __adbg_race_condition(const HANDLE process_handle, const HANDLE thread_handle)
{
    bool debugged = _read_context_strip(thread_handle);

    // forces DRs through the hook
    _Alignas(16) CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // current state first (to maintain other registers if necessary)
    if (!NT_SUCCESS(DbgNtGetContextThread(thread_handle, &ctx)))
        return debugged;

    // ctx.Dr0 = (DWORD64)(ULONG_PTR)stuff;
    // ctx.Dr7 = 0x55; 

    RaceContext rc = { 0 };
    rc.ContextPtr = &ctx;
    rc.Run = true;

    HANDLE race_thread = DbgCreateThread(process_handle, 0, __race, &rc, 0, NULL, NULL);
    if (!race_thread)
        return debugged;

    // yield
    LARGE_INTEGER delay = { 0 };
    delay.QuadPart = -10000LL; // 1 millisecond (10,000 * 100ns)
    DbgNtDelayExecution(FALSE, &delay);

    // pass the pointer to the kernel
    // a debugger may intercept this, strip the 0x10 bit, and pass the pointer to the real NtSetContextThread
    // while it does that, _race_function writes the 0x10 bit back into ctx
    DbgNtSetContextThread(thread_handle, &ctx);

    rc.Run = false;
    DbgNtWaitForSingleObject(race_thread, FALSE, NULL);
    DbgNtClose(race_thread);

    return debugged;
}