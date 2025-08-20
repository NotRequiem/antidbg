#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <psapi.h>

#ifdef _DEBUG
#define OutputDebugStringDbgOnly(S) OutputDebugString(S)
#else
#define OutputDebugStringDbgOnly(S) do {} while(0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	bool PageExceptionBreakpoint(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif
