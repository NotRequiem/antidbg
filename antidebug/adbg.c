/* Only reliable and tested methods, that can be done from user-mode, are included. */

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
#include "exceptions\unhexcp.h"
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
#include "memory\lowfraghp.h"
#include "memory\vrtalloc.h"

#include "object\clshandle.h"
#include "object\clsinvhandle.h"
#include "object\crtfile.h"
#include "object\dbgobj.h"
#include "object\loadlib.h"
#include "object\opnproc.h"
#include "object\prothnd.h"
#include "object\sysdbgctl.h"

DebugCheckResult debuggerChecks[] = {
    {"IsBeingDebugged", IsBeingDebugged, false},
    {"IsRemoteDebuggerPresent", IsRemoteDebuggerPresent, false},
    {"OutputDebugStringAPI", CheckOutputDebugString, false},
    {"DebuggerBreak", DebuggerBreak, false},
    {"int2D", int2D, false},
    {"int3", int3, false},
    {"POPFTrapFlag", POPFTrapFlag, false},
    {"StackSegmentRegister", StackSegmentRegister, false},
    // {"UnhandledExcepFilterTest", CheckUnhandledExcepFilter, false}, - Uncomment this if you're ok with having crashes when detecting debuggers
    {"RaiseDbgControl", RaiseDbgControl, false},
    {"PageExceptionBreakpoint", PageExceptionBreakpoint, false},
    {"IsDebuggerPresent_DebugObjectHandle", IsDebuggerPresent_DebugObjectHandle, false},
    {"KernelDebugger", KernelDebugger, false},
    {"NtGlobalFlag", NtGlobalFlag, false},
    {"IsDebuggerPresent_DebugFlags", IsDebuggerPresent_DebugFlags, false},
    {"ProcessHeap_Flags", ProcessHeapFlag, false},
    {"ProcessHeapForce_Flag", ProcessHeapForceFlag, false},
    {"IsHooked", IsHooked, false},
    {"API_Hooks", CheckModuleBounds, false},
    {"ReadOwnMemoryStack", ReadMemoryStack, false},
    {"PEB", CheckPEB, false},
    // {"LowFragmentationHeap", LowFragmentationHeap, false}, - Not too reliable, uncomment if you wanna have more antidebugging protection with some false flags in edge cases
    {"CheckNtQueryInformationProcess", CheckNtQueryInformationProcess, false},
    {"HardwareBreakpoint", HardwareBreakpoint, false},
    {"HardwareBreakpoint2", HardwareBreakPoint2, false},
    {"MemoryBreakpoint", MemoryBreakpoint, false},
    {"VirtualAlloc_MEM_WRITE_WATCH", WriteWatch, false},
    {"CheckCloseHandle", CheckCloseHandle, false},
    {"CheckCloseHandleWithInvalidHandle", CloseInvalidHandle, false},
    {"CheckCreateFile", CheckCreateFile, false},
    {"CheckNtQueryObject", CheckNtQueryObject, false},
    {"CheckLoadLibrary", CheckLoadLibrary, false},
    {"CheckOpenProcess", CheckOpenProcess, false},
    {"SetHandleInformation", ProtectedHandle, false},
    {"NtSystemDebugControl_Command", NtSystemDebugControl, false},
};

bool printDebugInfo = true;

bool IsProgramDebugged() {
    bool debuggerDetected = false;

    for (int i = 0; i < NUM_DEBUG_CHECKS; ++i) {
        debuggerChecks[i].result = debuggerChecks[i].functionPtr();
        if (debuggerChecks[i].result) {
            debuggerDetected = true;
            if (printDebugInfo) {
                printf("%s: Debugger detected!\n", debuggerChecks[i].functionName);
            }
            break;
        }
    }

    if (!debuggerDetected && printDebugInfo) {
        printf("No debugger detected.\n");
    }

    return debuggerDetected;
}
