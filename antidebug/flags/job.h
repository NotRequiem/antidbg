#pragma once

#include <windows.h>
#include <stdbool.h>
#include <psapi.h>

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_process_job();

#ifdef __cplusplus
}
#endif