#pragma once

#include <windows.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_parent_processes(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif