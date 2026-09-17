#pragma once

#include <windows.h>
#include <stdbool.h>

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_hardware_breakpoint(const HANDLE thread_handle);

#ifdef __cplusplus
}
#endif
