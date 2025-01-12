#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool MemoryBreakpoint(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif
