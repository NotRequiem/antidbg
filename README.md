# antidbg
My personal antidebugging library

`Example Usage:`

```
#include <stdio.h>

int main() {
    if (IsProgramDebugged()) {
        printf("Debugger detected!\n");
    } else {
        printf("No debugger detected.\n");
    }

    return 0;
}
```
