#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_instruction_count(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif
