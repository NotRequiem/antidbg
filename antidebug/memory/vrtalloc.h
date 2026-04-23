#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_write_watch(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif