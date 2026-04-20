#pragma once

#include <windows.h>
#include <stdbool.h>

#define MAX_SUSPEND_COUNT 127
#define STATUS_SUSPEND_COUNT_EXCEEDED ((NTSTATUS)0xC000004A)

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_suspension(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif