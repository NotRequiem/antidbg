# Advanced AntiDebugging Library for C/C++

antidbg is an advanced user-mode anti-debugging library for Windows, designed to detect debuggers without using unreliable/inaccurate checks (like timing checks, process name checks, etc)

The library is:
- Very easy to use (only one function call required)
- Directly syscalled, which means that most antidebugging checks can't be hooked from user-mode
- Optimized for officially supported Windows versions. For techniques with full compatibility for Windows Vista - Windows 11 and x86_32/WoW64, check the source files in https://github.com/NotRequiem/antidbg/commit/9d0dd9a8bac7d694a0f8f06bc24a78cd1aa953e4
- Designed for speed and minimal memory usage

## Features
**__1.__** Able to bypass thread creation hooking and hide user-mode threads from debuggers.

**__2.__** Able to detect debuggers with more than 30 different techniques:
  - 1: IsBeingDebugged
  - 2: IsRemoteDebuggerPresent
  - 3: DebuggerBreak
  - 4: int2D
  - 5: int3
  - 6: StackSegmentRegister
  - 7: PrefixHop
  - 8: RaiseDbgControl
  - 9: IsDebuggerPresent_DebugObjectHandle
  - 10: KernelDebugger
  - 11: NtGlobalFlag
  - 12: IsDebuggerPresent_DebugFlags
  - 13: ProcessHeap_Flags
  - 14: ProcessHeapForce_Flag
  - 15: DuplicatedHandles
  - 16: PEB (direct access without using api calls)
  - 17: CheckNtQueryInformationProcess
  - 18: HardwareBreakpoint
  - 19: HardwareBreakpoint2
  - 20: VirtualAlloc_MEM_WRITE_WATCH
  - 21: DebugActiveProcess
  - 22: CheckCloseHandle
  - 23: CheckCloseHandleWithInvalidHandle
  - 24: CheckNtQueryObject
  - 25: CheckOpenProcess
  - 26: SetHandleInformation
  - 27: NtSystemDebugControl_Command
  - 28: ReadOwnMemoryStack
  - 29: ProcessJob
  - 30: POPFTrapFlag
  - 31: MemoryBreakpoint
  - 32: PageExceptionBreakpoint
 
*If you're interested in more antidebug detections, this repository contains more tricks that were not included in production that you may find useful, such as code for Self-Debugging techniques and kernel debugger detections.*

**__3.__** Able to detect unusual memory writes by other analysis tools like sandboxes.

**__4.__** Monitorization of antidebugging thread priority.

**__5.__** Ability to randomize the time when protection routines will run.

## Detection Modes
> 1. Guard mode: A thread will start running in your program and monitor for attached debuggers infinitely. If a debugger is detected at any time, the program will forcefully exit while preventing other programs to stop the crash.

`Example Usage:`
```c
#include "adbg.h"

int main() {
    IsProgramBeingDebugged();

    return 0;
}
```

> 2. Single-run mode: A function that you can call at any time to detect if debuggers are attached to your process.

`Example Usage:`
```c
#include "adbg.h"

int main() {
    if (isProgramBeingDebugged()) {
        printf("Debugger detected.\n");
    }
    else {
        printf("No debugger was detected.\n");
    }

    return 0;
}
```

# Legal
I am not responsible nor liable for any damage you cause through any malicious usage of this project.

License: GNU GENERAL PUBLIC LICENSE, Version 2