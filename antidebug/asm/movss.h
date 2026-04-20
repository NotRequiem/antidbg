#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <intrin.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /* gcc/clang
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
    */
    /* MSVC
        unsigned __int64 flags = __readeflags();
        return (flags & 0x100) != 0;
    */

	bool __adbg_mov_ss();

#ifdef __cplusplus
}
#endif
