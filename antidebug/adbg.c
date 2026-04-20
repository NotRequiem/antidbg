#include "adbg.h"

checks_info debugger_checks[] = {
    {false, "IsBeingDebugged", .function_ptr = __adbg_is_debugger_present},
    {false, "IsRemoteDebuggerPresent", .function_with_process = __adbg_remote_debugger},
    {false, "int 2d", .function_ptr = __adbg_int2d},
    {false, "int 3", .function_ptr = __adbg_int3},
    {false, "ice", .function_with_thread = __adbg_ice},
    {false, "Stack Segment Register", .function_with_process = __adbg_ssr},
    {false, "prefix hop", .function_ptr = __adbg_prefix_hop},
    {false, "popf", .function_ptr = __adbg_popf},
    {false, "Raise Debug Control", .function_ptr = __adbg_dbg_control},
    {false, "Debug Object Handle", .function_with_process = __adbg_object_handle},
    {false, "Kernel Debugger", .function_ptr = __adbg_kernel_debugger},
    {false, "NtGlobalFlag", .function_ptr = __adbg_nt_global_flag},
    {false, "Debug Flags", .function_with_process = __adbg_debug_flags},
    {false, "Process Heap Flags", .function_ptr = __adbg_heap_flag},
    {false, "Process Heap Force Flag", .function_ptr = __adbg_heap_forceflag},
    {false, "Duplicated Handles", .function_with_process = __adbg_duplicate_handles},
    {false, "Parent Processes", .function_with_process = __adbg_parent_processes},
    {false, "PEB", .function_ptr = __adbg_peb},
    {false, "Debug Port", .function_with_process = __adbg_debug_port},
    {false, "Hardware Breakpoint", .function_with_thread = __adbg_hardware_breakpoint},
    {false, "MEM_WRITE_WATCH", .function_with_process = __adbg_write_watch},
    {false, "Invalid Handle", .function_ptr = __adbg_close_handle},
    {false, "NtQueryObject", .function_ptr = __adbg_query_object},
    {false, "NtOpenProcess", .function_ptr = __adbg_open_process},
    {false, "Protected Handle", .function_ptr = __adbg_protected_handle},
    {false, "NtSystemDebugControl", .function_with_process = __adbg_system_debug_control},
    {false, "Stack Memory", .function_ptr = __adbg_stack_memory},
    {false, "Process Job", .function_ptr = __adbg_process_job},
    {false, "Memory Breakpoint", .function_with_process = __adbg_memory_breakpoint},
    {false, "Page Exception Breakpoint", .function_with_process = __adbg_page_exception_breakpoint},
    {false, "Timing", .function_ptr = __adbg_timing_attack},
    {false, "Window", .function_ptr = __adbg_window},
    {false, "DBGP", .function_ptr = __adbg_dbgp},
    {false, "LBR", .function_with_process_and_thread = __adbg_lbr },
    {false, "Heap Magic", .function_ptr = __adbg_heap_magic},
    {false, "Working Set", .function_with_process = __adbg_working_set},
    {false, "Console Event", .function_ptr = __adbg_console_event},
    {false, "Thread Suspension", .function_with_process = __adbg_suspension},
    {false, "NtSetDebugFilterState", .function_with_process = __adbg_filter_state},
    {false, "Device Objects", .function_ptr = __adbg_device},
    {false, "Race Condition", .function_ptr = __adbg_race_condition}
};

#define NUM_DEBUG_CHECKS (sizeof(debugger_checks) / sizeof(debugger_checks[0]))

DWORD __stdcall __adbg(LPVOID lpParam) {
    const HANDLE process_handle = (HANDLE)(lpParam);
    const HANDLE thread_handle = (HANDLE)(-2LL);

    while (1) {
        for (int i = 0; i < NUM_DEBUG_CHECKS; ++i) {
            if (debugger_checks[i].function_with_process != NULL) {
                debugger_checks[i].result = debugger_checks[i].function_with_process(process_handle);
            }
            else if (debugger_checks[i].function_with_thread != NULL) {
                debugger_checks[i].result = debugger_checks[i].function_with_thread(thread_handle);
            }
            else if (debugger_checks[i].function_with_process_and_thread != NULL) {
                debugger_checks[i].result = debugger_checks[i].function_with_process_and_thread(process_handle, thread_handle);
            }
            else if (debugger_checks[i].function_ptr != NULL) {
                debugger_checks[i].result = debugger_checks[i].function_ptr();
            }

            if (debugger_checks[i].result) {
                __log("[!] Debugger detected in function: %s", debugger_checks[i].function_name);
                __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
            }
            else {
                __log("[+] %s passed", debugger_checks[i].function_name);
            }

            // ensure our thread priority was not tampered with
            THREAD_BASIC_INFORMATION tbi = { 0 };
            NTSTATUS status = DbgNtQueryInformationThread(thread_handle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
            if (status < 0) {
                SetLastError(status);
                __log_error("DbgNtQueryInformationThread");
            }

            LONG priority_increment = 1; //  THREAD_PRIORITY_ABOVE_NORMAL

            status = DbgNtSetInformationThread(thread_handle, ThreadBasePriority, &priority_increment, sizeof(LONG));
            if (status < 0) {
                SetLastError(status);
                __log_error("DbgNtSetInformationThread");
            }

            const uint64_t random_delay = __randomize(30, 900); // default windows clock runs at 64Hz (15.625ms); 15x2=30 gives us a good tick, and 900 is a multiple of 30

            LARGE_INTEGER delay = { 0 };
            const __int64 randomDelayMs64 = (__int64)random_delay;
            const __int64 conversion_factor = 10000;
            const __int64 result = -(randomDelayMs64 * conversion_factor);

            delay.QuadPart = result;

            DbgNtDelayExecution(FALSE, &delay);
        }
    }

    return 0;
}

void StartDebugProtection() {
    const HANDLE process_handle = (HANDLE)(-1LL);
    const HANDLE thread_handle = (HANDLE)(-2LL);

    DbgNtSetInformationThread(thread_handle, ThreadHideFromDebugger, NULL, 0);

    const PVOID veh = AddVectoredExceptionHandler(1, __global_handler);

    if (!veh) {
        __log_error("AddVectoredExceptionHandler");
        __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
    }

    __setup_protection(process_handle);

    DbgCreateThread(process_handle, 0, __adbg, (LPVOID)process_handle, 0, ((void*)0), ((void*)0));

    __start_monitor(process_handle);
}

bool isProgramBeingDebugged() 
{
    const HANDLE process_handle = (HANDLE)(-1LL);
    const HANDLE thread_handle = (HANDLE)(-2LL);

    for (int i = 0; i < NUM_DEBUG_CHECKS; ++i) {
        if (debugger_checks[i].function_with_process != NULL) {
            debugger_checks[i].result = debugger_checks[i].function_with_process(process_handle);
        }
        else if (debugger_checks[i].function_with_thread != NULL) {
            debugger_checks[i].result = debugger_checks[i].function_with_thread(thread_handle);
        }
        else if (debugger_checks[i].function_with_process_and_thread != NULL) {
            debugger_checks[i].result = debugger_checks[i].function_with_process_and_thread(process_handle, thread_handle);
        }
        else if (debugger_checks[i].function_ptr != NULL) {
            debugger_checks[i].result = debugger_checks[i].function_ptr();
        }

        if (debugger_checks[i].result) {
            __log("[!] Debugger detected in function: %s", debugger_checks[i].function_name);
            return true;
        }
        else {
            __log("[+] %s passed", debugger_checks[i].function_name);
        }
    }

    return false;
}

int main() {
    StartDebugProtection();
    return 0;
}