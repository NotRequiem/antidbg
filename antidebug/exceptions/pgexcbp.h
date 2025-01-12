#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <psapi.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DEBUG
#define OutputDebugStringDbgOnly(S) OutputDebugString(S)
#else
#define OutputDebugStringDbgOnly(S) do {} while(0)
#endif

	bool PageExceptionBreakpoint(HANDLE hProcess);

#ifdef __cplusplus
}
#endif
