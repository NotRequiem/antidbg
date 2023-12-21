# AntiDebugging Library for C/C++

`Example Usage:`

```
#include <stdio.h>
#include "adbg.h"

int main() {
    if (IsProgramDebugged()) {
        printf("Debugger detected!\n");
    } else {
        printf("No debugger detected.\n");
    }

    return 0;
}
```
