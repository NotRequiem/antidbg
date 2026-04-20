#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_debug_port(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif
