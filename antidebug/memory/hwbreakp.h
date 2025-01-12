#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool HardwareBreakpoint(const HANDLE hThread);

#ifdef __cplusplus
}
#endif
