#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <psapi.h>

#ifdef _DEBUG
	#define OutputDebugStringDbgOnly(S) OutputDebugString(S)
#else
	#define OutputDebugStringDbgOnly(S) do {} while(0)
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define PAGE_SIZE 0x1000

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_page_exception_breakpoint(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif
