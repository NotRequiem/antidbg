#include "adbg.h"

DWORD g_main_thread_id = 0;

checks_info debugger_checks[] = {
    {CHECK_VOID, "IsBeingDebugged", .function_ptr = __adbg_is_debugger_present},
    {CHECK_PROCESS, "IsRemoteDebuggerPresent", .function_with_process = __adbg_remote_debugger},
    {CHECK_VOID, "int 2d", .function_ptr = __adbg_int2d},
    {CHECK_VOID, "int 3", .function_ptr = __adbg_int3},
    {CHECK_THREAD, "ice", .function_ptr = __adbg_ice},
    {CHECK_PROCESS, "Stack Segment Register", .function_with_process = __adbg_ssr},
    {CHECK_VOID, "prefix hop", .function_ptr = __adbg_prefix_hop},
    {CHECK_VOID, "popf", .function_ptr = __adbg_popf},
    {CHECK_VOID, "Raise Debug Control", .function_ptr = __adbg_dbg_control},
    {CHECK_PROCESS, "Debug Object Handle", .function_with_process = __adbg_object_handle},
    {CHECK_VOID, "Kernel Debugger", .function_ptr = __adbg_kernel_debugger},
    {CHECK_VOID, "NtGlobalFlag", .function_ptr = __adbg_nt_global_flag},
    {CHECK_PROCESS, "Debug Flags", .function_with_process = __adbg_debug_flags},
    {CHECK_PROCESS, "Duplicated Handles", .function_with_process = __adbg_duplicate_handles},
    {CHECK_PROCESS, "Parent Processes", .function_with_process = __adbg_parent_processes},
    {CHECK_VOID, "PEB", .function_ptr = __adbg_peb},
    {CHECK_PROCESS, "Debug Port", .function_with_process = __adbg_debug_port},
    {CHECK_THREAD, "Hardware Breakpoint", .function_with_thread = __adbg_hardware_breakpoint},
    {CHECK_PROCESS, "MEM_WRITE_WATCH", .function_with_process = __adbg_write_watch},
    {CHECK_VOID, "Invalid Handle", .function_ptr = __adbg_close_handle},
    {CHECK_VOID, "NtQueryObject", .function_ptr = __adbg_query_object},
    {CHECK_VOID, "NtOpenProcess", .function_ptr = __adbg_open_process},
    {CHECK_VOID, "Protected Handle", .function_ptr = __adbg_protected_handle},
    {CHECK_PROCESS, "NtSystemDebugControl", .function_with_process = __adbg_system_debug_control},
    {CHECK_VOID, "Stack Memory", .function_ptr = __adbg_stack_memory},
    {CHECK_VOID, "Process Job", .function_ptr = __adbg_process_job},
    {CHECK_PROCESS, "Memory Breakpoint", .function_with_process = __adbg_memory_breakpoint},
    {CHECK_PROCESS, "Page Exception Breakpoint", .function_with_process = __adbg_page_exception_breakpoint},
    {CHECK_VOID, "Timing", .function_ptr = __adbg_timing_attack},
    {CHECK_VOID, "Window", .function_ptr = __adbg_window},
    {CHECK_PROCESS_THREAD, "LBR", .function_with_process_and_thread = __adbg_lbr },
    {CHECK_PROCESS, "Heap Magic", .function_with_process = __adbg_heap_magic},
    {CHECK_PROCESS, "Working Set", .function_with_process = __adbg_working_set},
    {CHECK_VOID, "Console Event", .function_ptr = __adbg_console_event},
    {CHECK_PROCESS, "Thread Suspension", .function_with_process = __adbg_suspension},
    {CHECK_PROCESS, "NtSetDebugFilterState", .function_with_process = __adbg_filter_state},
    {CHECK_VOID, "Device Objects", .function_ptr = __adbg_device},
    {CHECK_PROCESS_THREAD, "Race Condition", .function_with_process_and_thread = __adbg_race_condition},
    {CHECK_PROCESS, "Debugger Freeze", .function_with_process = __adbg_freeze_debugger},
    {CHECK_VOID, "Syscalls", .function_ptr = __adbg_check_syscalls},
    {CHECK_PROCESS, "Instruction Count", .function_with_process = __adbg_instruction_count},
    {CHECK_VOID, "OutputDebugString", .function_ptr = __adbg_output_dbg_str},
    {CHECK_VOID, "LoadLibrary", .function_ptr = __adbg_load_library}
};

#define NUM_DEBUG_CHECKS (sizeof(debugger_checks) / sizeof(debugger_checks[0]))

DWORD __stdcall __adbg(LPVOID lpParam) {
    const HANDLE process_handle = (HANDLE)(lpParam);
    HANDLE target_thread = NULL;

    CLIENT_ID cid = { 0 };
    cid.UniqueThread = (HANDLE)(ULONG_PTR)g_main_thread_id;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    DbgNtOpenThread(&target_thread, THREAD_ALL_ACCESS, &oa, &cid);

    while (1) {
        for (size_t i = 0; i < NUM_DEBUG_CHECKS; ++i) {
            switch (debugger_checks[i].type) {
                case CHECK_VOID:
                    debugger_checks[i].result = debugger_checks[i].function_ptr();
                    break;
                case CHECK_PROCESS:
                    debugger_checks[i].result = debugger_checks[i].function_with_process(process_handle);
                    break;
                case CHECK_THREAD:
                    // context-based checks like ICE and LBR could crash the main application thread because they are executed from the monitor thread
                    // so we force the monitor thread to run these context-modifying checks on itself 
                    debugger_checks[i].result = debugger_checks[i].function_with_thread((HANDLE)-2LL);
                    break;
                case CHECK_PROCESS_THREAD:
                    debugger_checks[i].result = debugger_checks[i].function_with_process_and_thread(process_handle, (HANDLE)-2LL);
                    break;
            }

            if (debugger_checks[i].result) {
                __log("[!] Debugger detected in function: %s", debugger_checks[i].function_name);
                __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
            }
            else {
                __log("[+] %s passed", debugger_checks[i].function_name);
            }
        }

        THREAD_BASIC_INFORMATION tbi = { 0 };
        DbgNtQueryInformationThread((HANDLE)-2LL, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
        LONG priority = 9;
        DbgNtSetInformationThread((HANDLE)-2LL, ThreadBasePriority, &priority, sizeof(LONG));

        const uint64_t random_delay = __randomize(30, 900);
        LARGE_INTEGER delay = { 0 };
        delay.QuadPart = -((__int64)random_delay * 10000);
        DbgNtDelayExecution(FALSE, &delay);
    }

    return 0;
}

void StartDebugProtection() {
    g_main_thread_id = GetCurrentThreadId();

    const HANDLE process_handle = (HANDLE)(-1LL);
    const HANDLE thread_handle = (HANDLE)(-2LL);
    DbgNtSetInformationThread(thread_handle, ThreadHideFromDebugger, NULL, 0);
    
    const PVOID veh = AddVectoredExceptionHandler(1, __global_handler);

    if (!veh) {
        __log_error("AddVectoredExceptionHandler");
        __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
    }
    __setup_protection(process_handle);

    DbgCreateThread(process_handle, 0, __adbg, (LPVOID)process_handle, 0, NULL, NULL);
    DbgCreateThread(process_handle, 0, (LPTHREAD_START_ROUTINE)__start_monitor, (LPVOID)process_handle, 0, NULL, NULL);
}

bool isProgramBeingDebugged()
{
    const HANDLE process_handle = (HANDLE)(-1LL);
    const HANDLE thread_handle = (HANDLE)(-2LL);

    for (size_t i = 0; i < NUM_DEBUG_CHECKS; ++i) {
        switch (debugger_checks[i].type) {
        case CHECK_VOID:
            debugger_checks[i].result = debugger_checks[i].function_ptr();
            break;
        case CHECK_PROCESS:
            debugger_checks[i].result = debugger_checks[i].function_with_process(process_handle);
            break;
        case CHECK_THREAD:
            debugger_checks[i].result = debugger_checks[i].function_with_thread(thread_handle);
            break;
        case CHECK_PROCESS_THREAD:
            debugger_checks[i].result = debugger_checks[i].function_with_process_and_thread(process_handle, thread_handle);
            break;
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
    SleepEx(0xFFFFFFFF, 0);
    return 0; 
}
