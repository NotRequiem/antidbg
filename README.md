# AntiDebugging Library for C/C++

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
