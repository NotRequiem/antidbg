#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

#define EXCEPTION_TRAP_FLAG 0x80000001

#ifdef __cplusplus
extern "C" {
#endif

    /*
    * check whether is EXCEPTION_SINGLE_STEP
    __asm
            {
                pushfd
                mov dword ptr [esp], 0x100
                popfd
                nop
            }
    */

	bool __adbg_popf();

#ifdef __cplusplus
}
#endif

