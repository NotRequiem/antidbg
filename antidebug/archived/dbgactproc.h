#pragma once

#include <windows.h>
#include <stdbool.h>

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef DEBUG_ALL_ACCESS
	#define DEBUG_ALL_ACCESS 0x1F000F
#endif

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_child_debug_event();

#ifdef __cplusplus
}
#endif
