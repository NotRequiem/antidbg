#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool HardwareBreakPoint2(const HANDLE hThread, const HANDLE hProcess);

#ifdef __cplusplus
}
#endif