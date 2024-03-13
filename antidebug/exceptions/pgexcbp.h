#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <psapi.h>

#ifdef _DEBUG
#define OutputDebugStringDbgOnly(S) OutputDebugString(S)
#else
#define OutputDebugStringDbgOnly(S) do {} while(0)
#endif

	void** executablePages = NULL;
	size_t executablePagesCount = 0;

	bool PageExceptionBreakpoint();

#ifdef __cplusplus
}
#endif
