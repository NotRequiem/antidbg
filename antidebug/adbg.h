#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "core\thrmng.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        bool result;
        const char* functionName;
        union {
            bool (*functionPtr)();
            bool (*functionPtrWithProcess)(HANDLE);
            bool (*functionPtrWithThread)(HANDLE);
            bool (*functionPtrWithProcessAndThread)(HANDLE, HANDLE);
        };
    } DebugCheckResult;

    extern DebugCheckResult debuggerChecks[];

    void IsProgramBeingDebugged(); // guard mode
    bool isProgramBeingDebugged(); // single run mode

#ifdef __cplusplus
}
#endif