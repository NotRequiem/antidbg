#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

#define EXCEPTION_TRAP_FLAG 0x80000001

#ifdef __cplusplus
extern "C" {
#endif

bool POPFTrapFlag();

#ifdef __cplusplus
}
#endif

