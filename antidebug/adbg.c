#include "adbg.h"

#include "api\dbgpresent.h"
#include "api\rdbgpresent.h"
#include "api\outdbgstring.h"

#include "asm\dbgbreak.h"
#include "asm\int2d.h"
#include "asm\int3.h"
#include "asm\popf.h"
#include "asm\sckreg.h"

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

#include "hook\ishooked.h"
#include "hook\api.h"

#include "memory\hwbreakp.h"
#include "memory\membreakp.h"
#include "memory\readstck.h"
#include "memory\peb.h"
#include "memory\vrtalloc.h"

#include "object\clshandle.h"
#include "object\clsinvhandle.h"
#include "object\crtfile.h"
#include "object\dbgobj.h"
#include "object\opnproc.h"
#include "object\prothnd.h"
#include "object\sysdbgctl.h"

DebugCheckResult debuggerChecks[] = {
    {false, "IsBeingDebugged", IsBeingDebugged},
    {false, "IsRemoteDebuggerPresent", IsRemoteDebuggerPresent},
    {false, "OutputDebugStringAPI", CheckOutputDebugString},
    {false, "DebuggerBreak", DebuggerBreak},
    {false, "int2D", int2D},
    {false, "int3", int3},
    {false, "POPFTrapFlag", POPFTrapFlag},
    {false, "StackSegmentRegister", StackSegmentRegister},
    {false, "RaiseDbgControl", RaiseDbgControl},
    {false, "MemoryBreakpoint", MemoryBreakpoint},
    {false, "PageExceptionBreakpoint", PageExceptionBreakpoint},
    {false, "IsDebuggerPresent_DebugObjectHandle", IsDebuggerPresent_DebugObjectHandle},
    {false, "KernelDebugger", KernelDebugger},
    {false, "NtGlobalFlag", NtGlobalFlag},
    {false, "IsDebuggerPresent_DebugFlags", IsDebuggerPresent_DebugFlags},
    {false, "ProcessHeap_Flags", ProcessHeapFlag},
    {false, "ProcessHeapForce_Flag", ProcessHeapForceFlag},
    {false, "IsHooked", IsHooked},
    {false, "API_Hooks", CheckModuleBounds},
    {false, "ReadOwnMemoryStack", ReadMemoryStack},
    {false, "PEB", CheckPEB},
    {false, "CheckNtQueryInformationProcess", CheckNtQueryInformationProcess},
    {false, "HardwareBreakpoint", HardwareBreakpoint},
    {false, "HardwareBreakpoint2", HardwareBreakPoint2},
    {false, "VirtualAlloc_MEM_WRITE_WATCH", WriteWatch},
    {false, "CheckCloseHandle", CheckCloseHandle},
    {false, "CheckCloseHandleWithInvalidHandle", CloseInvalidHandle},
  //{false, "CheckCreateFile", CheckCreateFile}, -> Removed because if you open the program with SystemInformer, this technique flags it
    {false, "CheckNtQueryObject", CheckNtQueryObject},
    {false, "CheckOpenProcess", CheckOpenProcess},
    {false, "SetHandleInformation", ProtectedHandle},
    {false, "NtSystemDebugControl_Command", NtSystemDebugControl},
};

#define NUM_DEBUG_CHECKS (sizeof(debuggerChecks) / sizeof(debuggerChecks[0]))

typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
    );

pfnNtSetInformationThread pNtSetInformationThread = NULL;

bool HideThreadFromDebugger() {
    NTSTATUS status = pNtSetInformationThread(
        NtCurrentThread,
        ThreadHideFromDebugger,
        NULL,
        0
    );

    return NT_SUCCESS(status);
}

static DWORD WINAPI __spectrum_adbg(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);

    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) pNtSetInformationThread = (pfnNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
    if (pNtSetInformationThread) HideThreadFromDebugger();
    

    while (1) {
        for (int i = 0; i < NUM_DEBUG_CHECKS; ++i) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtr();
            if (debuggerChecks[i].result) {
                printf("%s: Debugger detected!\n", debuggerChecks[i].functionName);
                __fastfail(1);
            }
        }

        Sleep(1000);
    }

    return 0;
}

void IsSpectrumDebugged() {
    HANDLE hThread = CreateThread(NULL, 0, __spectrum_adbg, NULL, 0, NULL);
    if (hThread == NULL) {
        fprintf(stderr, "Error creating thread: %lu\n", GetLastError());
        return;
    }

    CloseHandle(hThread);   
}
