#pragma once

#include <windows.h>
#include <stdbool.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_duplicate_handles(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif

