#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

    LONG CALLBACK VectoredDebuggerCheck(PEXCEPTION_POINTERS pExceptionInfo);

#ifdef __cplusplus
}
#endif