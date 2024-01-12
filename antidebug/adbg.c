/* Only reliable and tested methods, that can be done from user-mode in x64 bits, are included. Im still developing the rest. */

#include "adbg.h"

#include "api\dbgpresent.h"
#include "api\rdbgpresent.h"

#include "asm\dbgbreak.h"
#include "asm\int2d.h"
#include "asm\int3.h"
#include "asm\popf.h"
#include "asm\sckreg.h"

#include "exceptions\raiseexc.h"

#include "flags\dbgobjhandle.h"
#include "flags\kerneldbg.h"
#include "flags\procdbgflag.h"
#include "flags\procdbgport.h"

#include "hook\ishooked.h"

#include "memory\hwbreakp.h"

#include "object\clshandle.h"
#include "object\crtfile.h"
#include "object\dbgobj.h"
#include "object\loadlib.h"
#include "object\opnproc.h"

DebugCheckResult debuggerChecks[] = {
    {"IsRemoteDebuggerPresent", IsRemoteDebuggerPresent, false},
    {"DebuggerBreak", DebuggerBreak, false},
    {"int2D", int2D, false},
    {"int3", int3, false},
    {"POPFTrapFlag", POPFTrapFlag, false},
    {"StackSegmentRegister", StackSegmentRegister, false},
    {"RaiseDbgControl", RaiseDbgControl, false},
    {"IsDebuggerPresent_DebugObjectHandle", IsDebuggerPresent_DebugObjectHandle, false},
    {"KernelDebugger", KernelDebugger, false},
    {"IsDebuggerPresent_DebugFlags", IsDebuggerPresent_DebugFlags, false},
    {"IsHooked", IsHooked, false},
    {"CheckNtQueryInformationProcess", CheckNtQueryInformationProcess, false},
    {"HardwareBreakpoint", HardwareBreakpoint, false},
    {"CheckCloseHandle", CheckCloseHandle, false},
    {"CheckCreateFile", CheckCreateFile, false},
    {"CheckNtQueryObject", CheckNtQueryObject, false},
    {"CheckLoadLibrary", CheckLoadLibrary, false},
    {"CheckOpenProcess", CheckOpenProcess, false},
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
