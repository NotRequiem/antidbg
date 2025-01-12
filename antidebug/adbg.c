#include "adbg.h"
#include "core\syscall.h"

#include "api\dbgpresent.h"
#include "api\rdbgpresent.h"
#include "api\job.h"

#include "asm\dbgbreak.h"
#include "asm\int2d.h"
#include "asm\int3.h"
#include "asm\sckreg.h"
#include "asm\prehop.h"
#include "asm\popf.h"

#include "exceptions\raiseexc.h"
#include "exceptions\hwbreakp2.h"
#include "exceptions\pgexcbp.h"

#include "flags\dbgobjhandle.h"
#include "flags\kerneldbg.h"
#include "flags\ntglobalflag.h"
#include "flags\procdbgflag.h"
#include "flags\procdbgport.h"
#include "flags\prochpflag.h"
#include "flags\prochpforceflag.h"
#include "flags\duphnd.h"

#include "memory\hwbreakp.h"
#include "memory\readstck.h"
#include "memory\peb.h"
#include "memory\vrtalloc.h"
#include "memory\membreakp.h"

#include "object\clshandle.h"
#include "object\clsinvhandle.h"
#include "object\dbgobj.h"
#include "object\opnproc.h"
#include "object\prothnd.h"
#include "object\sysdbgctl.h"

DebugCheckResult debuggerChecks[] = {
    {false, "IsBeingDebugged", .functionPtr = IsBeingDebugged},
    {false, "IsRemoteDebuggerPresent", .functionPtrWithProcess = IsRemoteDebuggerPresent},
    {false, "DebuggerBreak", .functionPtr = DebuggerBreak},
    {false, "int2D", .functionPtr = int2D},
    {false, "int3", .functionPtr = int3},
    {false, "StackSegmentRegister", .functionPtrWithThread = StackSegmentRegister},
    {false, "PrefixHop", .functionPtr = PrefixHop},
    {false, "RaiseDbgControl", .functionPtr = RaiseDbgControl},
    {false, "IsDebuggerPresent_DebugObjectHandle", .functionPtrWithProcess = IsDebuggerPresent_DebugObjectHandle},
    {false, "KernelDebugger", .functionPtr = KernelDebugger},
    {false, "NtGlobalFlag", .functionPtr = NtGlobalFlag},
    {false, "IsDebuggerPresent_DebugFlags", .functionPtrWithProcess = IsDebuggerPresent_DebugFlags},
    {false, "ProcessHeap_Flags", .functionPtr = ProcessHeapFlag},
    {false, "ProcessHeapForce_Flag", .functionPtr = ProcessHeapForceFlag},
    {false, "DuplicatedHandles", .functionPtr = DuplicatedHandles},
    {false, "PEB", .functionPtr = CheckPEB},
    {false, "CheckNtQueryInformationProcess", .functionPtr = CheckNtQueryInformationProcess},
    {false, "HardwareBreakpoint", .functionPtr = HardwareBreakpoint},
    {false, "HardwareBreakpoint2", .functionPtrWithProcessAndThread = HardwareBreakPoint2},
    {false, "VirtualAlloc_MEM_WRITE_WATCH", .functionPtr = WriteWatch},
    {false, "CheckCloseHandle", .functionPtr = CheckCloseHandle},
    {false, "CheckCloseHandleWithInvalidHandle", .functionPtr = CloseInvalidHandle},
    {false, "CheckNtQueryObject", .functionPtr = CheckNtQueryObject},
    {false, "CheckOpenProcess", .functionPtr = CheckOpenProcess},
    {false, "SetHandleInformation", .functionPtr = ProtectedHandle},
    {false, "NtSystemDebugControl_Command", .functionPtr = NtSystemDebugControl},
    {false, "ReadOwnMemoryStack", .functionPtr = ReadMemoryStack},
    {false, "ProcessJob", .functionPtr = ProcessJob},
    {false, "POPFTrapFlag", .functionPtr = POPFTrapFlag},
    {false, "MemoryBreakpoint", .functionPtr = MemoryBreakpoint},
    {false, "PageExceptionBreakpoint", .functionPtrWithProcess = PageExceptionBreakpoint},
};

#define NUM_DEBUG_CHECKS (sizeof(debuggerChecks) / sizeof(debuggerChecks[0]))

DWORD __stdcall __adbg(LPVOID lpParam) {
    const HANDLE hProcess = (HANDLE)(lpParam);
    const HANDLE hThread = GetCurrentThread();
    const char* arg = (const char*)lpParam;

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

            // Ensure our thread priority was not tampered with
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

            // Generate a random delay to avoid attackers from predicting when checks will run
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

    return 0;
}

void IsProgramBeingDebugged() {
    const HANDLE hProcess = GetCurrentProcess();
    const HANDLE hThread = SpectrumCreateThread(GetCurrentProcess(), 0, __adbg, (LPVOID)hProcess, 0, ((void*)0), ((void*)0));
    WaitForSingleObject(hThread, INFINITE); // or keep running your main thread

    if (hThread)
        DbgNtClose(hThread);
    else
        printf("[-] Failed to create anti-debug thread\n.");
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

    return false;
}

int main() {
    // Single-run mode
    if (isProgramBeingDebugged()) {
        printf("[+] Debugger detected.\n");
    }
    else {
        printf("[-] No debugger was detected.\n");
    }

    // Guard mode
    IsProgramBeingDebugged();

    return 0;
}
