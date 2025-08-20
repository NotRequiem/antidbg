#include "adbg.h"

DebugCheckResult debuggerChecks[] = {
    {false, "IsBeingDebugged", .functionPtr = IsBeingDebugged},
    {false, "IsRemoteDebuggerPresent", .functionPtrWithProcess = IsRemoteDebuggerPresent},
    {false, "DebuggerBreak", .functionPtr = DebuggerBreak},
    {false, "int2D", .functionPtr = int2D},
    {false, "int3", .functionPtr = int3},
    {false, "StackSegmentRegister", .functionPtrWithThread = StackSegmentRegister},
    {false, "PrefixHop", .functionPtr = PrefixHop},
    {false, "RaiseDbgControl", .functionPtr = RaiseDbgControl},
    {false, "DebugObjectHandle", .functionPtrWithProcess = DebugObjectHandle},
    {false, "KernelDebugger", .functionPtr = KernelDebugger},
    {false, "NtGlobalFlag", .functionPtr = NtGlobalFlag},
    {false, "DebugFlags", .functionPtrWithProcess = DebugFlags},
    {false, "ProcessHeap_Flags", .functionPtr = ProcessHeapFlag},
    {false, "ProcessHeapForce_Flag", .functionPtr = ProcessHeapForceFlag},
    {false, "DuplicatedHandles", .functionPtrWithProcess = DuplicatedHandles},
    {false, "ParentProcesses", .functionPtrWithProcess = ParentProcesses},
    {false, "NtSetLdtEntries", .functionPtr = CheckNtSetLdtEntries},
    {false, "PEB", .functionPtr = CheckPEB},
    {false, "DebugPort", .functionPtrWithProcess = DebugPort},
    {false, "HardwareBreakpoint", .functionPtrWithThread = HardwareBreakpoint},
    {false, "HardwareBreakpoint2", .functionPtrWithProcessAndThread = HardwareBreakPoint2},
    {false, "VirtualAlloc_MEM_WRITE_WATCH", .functionPtr = WriteWatch},
    {false, "InvalidHandle", .functionPtr = CheckCloseHandle},
    {false, "NtQueryObject", .functionPtr = CheckNtQueryObject},
    {false, "OpenProcess", .functionPtr = CheckOpenProcess},
    {false, "SetHandleInformation", .functionPtr = ProtectedHandle},
    {false, "NtSystemDebugControl", .functionPtr = NtSystemDebugControl},
    {false, "ReadOwnMemoryStack", .functionPtr = ReadMemoryStack},
    {false, "ProcessJob", .functionPtr = ProcessJob},
    {false, "POPFTrapFlag", .functionPtr = POPFTrapFlag},
    {false, "MemoryBreakpoint", .functionPtrWithProcess = MemoryBreakpoint},
    {false, "PageExceptionBreakpoint", .functionPtrWithProcess = PageExceptionBreakpoint},
    {false, "Timing", .functionPtr = TimingAttacks},
    {false, "Window", .functionPtr = CheckWindow}
};

#define NUM_DEBUG_CHECKS (sizeof(debuggerChecks) / sizeof(debuggerChecks[0]))


DWORD __stdcall __adbg(LPVOID lpParam) {
    const HANDLE hProcess = (HANDLE)(lpParam);
    const HANDLE hThread = GetCurrentThread();

    srand((unsigned int)time(NULL));

    while (1) {
        for (int i = 0; i < NUM_DEBUG_CHECKS; ++i) {
            if (debuggerChecks[i].functionPtrWithProcess != NULL) {
                debuggerChecks[i].result = debuggerChecks[i].functionPtrWithProcess(hProcess);
            }
            else if (debuggerChecks[i].functionPtrWithThread != NULL) {
                debuggerChecks[i].result = debuggerChecks[i].functionPtrWithThread(hThread);
            }
            else if (debuggerChecks[i].functionPtrWithProcessAndThread != NULL) {
                debuggerChecks[i].result = debuggerChecks[i].functionPtrWithProcessAndThread(hProcess, hThread);
            }
            else if (debuggerChecks[i].functionPtr != NULL) {
                debuggerChecks[i].result = debuggerChecks[i].functionPtr();
            }

            if (debuggerChecks[i].result) {
#ifdef _DEBUG
                printf("[!] Debugger detected in function: %s\n", debuggerChecks[i].functionName);
#endif
                __fastfail(EXIT_SUCCESS);
            }

            // ensure our thread priority was not tampered with
            const int currentPriority = GetThreadPriority(hThread);
            if (currentPriority == THREAD_PRIORITY_ERROR_RETURN) {
#ifdef _DEBUG
                printf("[-] Failed to query thread priority. Error: %d\n", GetLastError());
#endif
            }

            if (currentPriority != THREAD_PRIORITY_NORMAL) {
                if (!SetThreadPriority(hThread, THREAD_PRIORITY_NORMAL)) {
#ifdef _DEBUG
                    printf("[-] Failed to set thread priority. Error: %d\n", GetLastError());
#endif
                }
            }

            // random delay to avoid attackers from predicting when checks will run
            const DWORD minDelayMs = 500;
            const DWORD maxDelayMs = 2000;
            const DWORD randomDelayMs = minDelayMs + (rand() % (maxDelayMs - minDelayMs + 1));

            LARGE_INTEGER delay = { 0 };
            const __int64 randomDelayMs64 = (__int64)randomDelayMs;
            const __int64 conversionFactor = 10000;
            const __int64 result = -(randomDelayMs64 * conversionFactor);

            delay.QuadPart = result;

            DbgNtDelayExecution(FALSE, &delay);
        }
    }

    DbgNtClose(hProcess); // never reached but ok
    return 0;
}


void StartDebugProtection() {
    const PVOID hVeh = AddVectoredExceptionHandler(1, VectoredDebuggerCheck);
    if (!hVeh) {
        __fastfail(STATUS_ACCESS_VIOLATION);
    }

    StartAttachProtection();
    const HANDLE hProcess = GetCurrentProcess();
    DbgCreateThread(GetCurrentProcess(), 0, __adbg, (LPVOID)hProcess, 0, ((void*)0), ((void*)0));
    StartMemoryTracker(hProcess);
}


bool isProgramBeingDebugged() {
    const HANDLE hProcess = GetCurrentProcess();
    const HANDLE hThread = GetCurrentThread();

    for (int i = 0; i < NUM_DEBUG_CHECKS; ++i) {
        if (debuggerChecks[i].functionPtrWithProcess != NULL) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtrWithProcess(hProcess);
        }
        else if (debuggerChecks[i].functionPtrWithThread != NULL) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtrWithThread(hThread);
        }
        else if (debuggerChecks[i].functionPtrWithProcessAndThread != NULL) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtrWithProcessAndThread(hProcess, hThread);
        }
        else if (debuggerChecks[i].functionPtr != NULL) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtr();
        }

        if (debuggerChecks[i].result) {
#ifdef _DEBUG
            printf("[!] Debugger detected in function: %s\n", debuggerChecks[i].functionName);
#endif
            return true;
        }
    }

    DbgNtClose(hProcess);
    DbgNtClose(hThread);
    return false;
}