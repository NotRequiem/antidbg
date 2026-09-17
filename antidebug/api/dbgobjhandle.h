#pragma once

#include <windows.h>
#include <stdbool.h>

#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_object_handle(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif
