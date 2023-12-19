/* Only reliable and tested methods, that can be done from user-mode in x64 bits, are included. Im still developing the rest. */

#include "adbg.h"

#include "api\dbgpresent.h"
#include "api\rdbgpresent.h"

#include "asm\dbgbreak.h"
#include "asm\int2d.h"
#include "asm\int3.h"
#include "asm\popf.h"
#include "asm\sckreg.h"

#include "exceptions\dbgprintex.h"
#include "exceptions\raiseexc.h"

#include "flags\dbgobjhandle.h"
#include "flags\kerneldbg.h"
#include "flags\procdbgflag.h"
#include "flags\procdbgport.h"

#include "memory\hwbreakp.h"
#include "memory\membreakp.h"

#include "object\clshandle.h"
#include "object\crtfile.h"
#include "object\dbgobj.h"
#include "object\loadlib.h"

bool IsProgramDebugged() {
    return IsDebuggerPresent() || IsRemoteDebuggerPresent() ||
           DebuggerBreak() || int2D() || int3() || POPFTrapFlag() ||
           StackSegmentRegister() || DBG_PRINTEXCEPTION() || RaiseDbgControl() ||
           IsDebuggerPresent_DebugObjectHandle() || KernelDebugger() ||
           IsDebuggerPresent_DebugFlags() || CheckNtQueryInformationProcess() ||
           HardwareBreakpoint() || MemoryBreakpoint() || CheckCloseHandle() ||
           CheckCreateFile() || CheckNtQueryObject() || CheckLoadLibrary();
}

/* 

* ================
* EXAMPLE USAGE
* ================

#include <stdio.h>

int main() {
    if (IsSpectrumDebugged()) {
        printf("Debugger detected!\n");
    } else {
        printf("No debugger detected.\n");
    }

    return 0;
}

*/