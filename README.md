# AntiDebugging Library for C/C++

antidbg is a PoC of a x64 user-mode anti-debugging library for Windows, designed to protect any software from debugging.

The library is:
- Very easy to use (only one function call required)
- Directly syscalled, which means that most antidebugging checks can't be hooked/intercepted from user-mode
- Optimized for officially supported Windows versions and AMD64 only.
- Designed for speed and minimal memory usage
- Compatible with any C and C++ standard

## Features
**__1.__** Able to bypass thread creation hooking and hide user-mode threads from debuggers.

**__2.__** Able to detect debuggers with more than 30 different tricks:
  - 1: IsBeingDebugged
  - 2: IsRemoteDebuggerPresent
  - 3: DebuggerBreak
  - 4: int2D
  - 5: int3
  - 6: StackSegmentRegister
  - 7: PrefixHop
  - 8: RaiseDbgControl
  - 9: DebugObjectHandle
  - 10: KernelDebugger
  - 11: NtGlobalFlag
  - 12: DebugFlags
  - 13: ProcessHeapFlags
  - 14: ProcessHeapForceFlag
  - 15: DuplicatedHandles
  - 16: PEB (direct memory access without using OS api calls)
  - 17: ProcessDebugPort
  - 18: HardwareBreakpoint
  - 19: HardwareBreakpoint2
  - 20: MEM_WRITE_WATCH
  - 21: DebugActiveProcess
  - 22: InvalidHandle
  - 23: NtQueryObject
  - 24: NtOpenProcess
  - 25: SetHandleInformation
  - 26: NtSystemDebugControl_Command
  - 27: ReadOwnMemoryStack
  - 28: ProcessJob
  - 29: POPFTrapFlag
  - 30: MemoryBreakpoint (PAGE_GUARD)
  - 31: PageExceptionBreakpoint
  - 32: Timing attacks
  - 33: Window analysis
  - 34: Thread start address
  - 35: Parent process 

**__3.__** Able to detect unusual memory writes by other analysis tools like sandboxes.

**__4.__** Monitorization of antidebugging thread priority and self-integrity.

**__5.__** Ability to randomize the time when protection routines will run.

**__6.__** Prevention, not only detection, of debuggers from being attached.

**__7.__** Protects the software from memory injections done by debuggers.

**__8.__** Continuous tracking of virtual memory with hardware-accelerated hashing to detect software breakpoints and inline hooks.

**__9.__** Runs a special routine before your program's entrypoint even starts to detect if a debugger is attached.

**__10.__** Automatic handling of any exception in your software without interfering with other program's handlers.

## Detection Modes
> 1. Guard mode:A thread will start running in your program and continuously monitor for attached debuggers. If a debugger is detected at any time, the program will forcefully exit while preventing other programs from stopping the crash.

`Example Usage:`
```c
#include "adbg.h"

int main() {
    StartDebugProtection();

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

# Notes
The library is fully supported on MSVC, the syscall core for other compilers like MinGW-w64, GCC and Clang is in experimental phase.
CMake generation is experimental.

# Legal
I am not responsible nor liable for any damage you cause through any malicious usage of this project.

License: GNU GENERAL PUBLIC LICENSE, Version 2