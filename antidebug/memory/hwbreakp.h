#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_hardware_breakpoint(const HANDLE thread_handle);

#ifdef __cplusplus
}
#endif
