/* Only reliable and tested methods, that can be done from user-mode, are included.*/

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

#include "flags\dbgobjhandle.h"
#include "flags\kerneldbg.h"
#include "flags\procdbgflag.h"
#include "flags\procdbgport.h"
#include "flags\prochpflag.h"
#include "flags\prochpforceflag.h"

#include "hook\ishooked.h"

#include "memory\hwbreakp.h"
#include "memory\readstck.h"
#include "memory\peb.h"
#include "memory\ntglobalflag.h"
#include "memory\lowfraghp.h"

#include "object\clshandle.h"
#include "object\clsinvhandle.h"
#include "object\crtfile.h"
#include "object\dbgobj.h"
#include "object\loadlib.h"
#include "object\opnproc.h"
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
    {"UnhandledExcepFilterTest", CheckUnhandledExcepFilter, false},
    {"RaiseDbgControl", RaiseDbgControl, false},
    {"IsDebuggerPresent_DebugObjectHandle", IsDebuggerPresent_DebugObjectHandle, false},
    {"KernelDebugger", KernelDebugger, false},
    {"IsDebuggerPresent_DebugFlags", IsDebuggerPresent_DebugFlags, false},
    {"ProcessHeap_Flags", ProcessHeapFlag, false},
    {"ProcessHeapForce_Flag", ProcessHeapForceFlag, false},
    {"IsHooked", IsHooked, false},
    {"ReadOwnMemoryStack", ReadMemoryStack, false},
    {"PEB", PEB, false},
    {"NtGlobalFlag", NtGlobalFlag, false},
    {"LowFragmentationHeap", LowFragmentationHeap, false},
    {"CheckNtQueryInformationProcess", CheckNtQueryInformationProcess, false},
    {"HardwareBreakpoint", HardwareBreakpoint, false},
    {"HardwareBreakpoint2", HardwareBreakPoint2, false},
    {"CheckCloseHandle", CheckCloseHandle, false},
    {"CheckCloseHandleWithInvalidHandle", CloseInvalidHandle, false},
    {"CheckCreateFile", CheckCreateFile, false},
    {"CheckNtQueryObject", CheckNtQueryObject, false},
    {"CheckLoadLibrary", CheckLoadLibrary, false},
    {"CheckOpenProcess", CheckOpenProcess, false},
    {"NtSystemDebugControl_Command", NtSystemDebugControl, false},
};

bool IsProgramDebugged() {
    for (int i = 0; i < sizeof(debuggerChecks) / sizeof(debuggerChecks[0]); ++i) {
        debuggerChecks[i].result = debuggerChecks[i].functionPtr();
        if (debuggerChecks[i].result) {
            printf("%s: Debugger detected!\n", debuggerChecks[i].functionName);
            return true;
        }
    }
    printf("No debugger detected.\n");
    return false;
}
