#ifndef ADBG_H
#define ADBG_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if _WIN32 || _WIN64
#if _WIN64
#define BIT64
#else
#define BIT32
#endif
#endif

#define NUM_DEBUG_CHECKS (sizeof(debuggerChecks) / sizeof(debuggerChecks[0]))

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
