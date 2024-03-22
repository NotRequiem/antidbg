# AntiDebugging Library for C/C++

## Compatibility
> This library is compatible with:
- **__1.__** Any C or C++ standard
- **__2.__** Any Windows version and/or build ranging from Windows Vista to Windows 11
- **__3.__** Any C/C++ compiler
- **__4.__** Any processor architecture (32 or 64 bits)
  
`Example Usage 1:`

```
#include "adbg.h"

int main() {
    IsProgramDebugged();
    return 0;
}
```

`Example Usage 2:`

```
#include "adbg.h"

int main() {
    if (IsProgramDebugged()) {
        printf("The program is being debugged.\n");
        // do something, example: exit(1);
    }
    else {
        printf("The program is NOT debugged.\n");
        // continue execution here
    }
    
    // or continue execution here
    return 0;
}
```

If you do not want the boolean function to print anything when a debugger is detected, you can simply set `printDebugInfo` to false:

```
#include "adbg.h"

int main() {
    printDebugInfo = false;
    IsProgramDebugged();
    return 0;
}
```
