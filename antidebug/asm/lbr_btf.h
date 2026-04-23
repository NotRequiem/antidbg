#pragma once

#include <stdio.h>
#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_lbr(const HANDLE process_handle, const HANDLE thread_handle);

#ifdef __cplusplus
}
#endif
