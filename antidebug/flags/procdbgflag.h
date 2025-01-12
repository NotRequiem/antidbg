#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool IsDebuggerPresent_DebugFlags(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif
