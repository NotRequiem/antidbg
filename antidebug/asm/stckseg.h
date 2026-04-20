#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_ssr(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif
