#include "movss.h"

bool mov_ss()
{

#ifdef _WIN64
#else
    _asm
    {
        push ss;
        pop ss;
        pushfd;
        test byte ptr[esp + 1], 1;
        jne fnd;
        jmp end;
    fnd:
        mov found, 1;
    end:
        nop;
    }
#endif

    unsigned __int64 flags = __readeflags();
    return (flags & 0x100) != 0;
}