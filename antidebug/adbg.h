#ifndef ADBG_H
#define ADBG_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        const char* functionName;
        bool (*functionPtr)();
        bool result;
    } DebugCheckResult;

    extern DebugCheckResult debuggerChecks[];

    bool IsProgramDebugged();

#ifdef __cplusplus
}
#endif

#endif
