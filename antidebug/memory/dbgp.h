#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef MAKEFOURCC
    #define MAKEFOURCC(ch0, ch1, ch2, ch3) \
        ((DWORD)(unsigned char)(ch0) | ((DWORD)(unsigned char)(ch1) << 8) | \
         ((DWORD)(unsigned char)(ch2) << 16) | ((DWORD)(unsigned char)(ch3) << 24))
#endif

#ifdef __cplusplus
extern "C" {
#endif

    bool __adbg_dbgp();

#ifdef __cplusplus
}
#endif
