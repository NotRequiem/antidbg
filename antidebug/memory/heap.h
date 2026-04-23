#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#if defined(__clang__) || defined(__GNUC__)
	#define _force_inline __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
	#define _force_inline __forceinline
#else
	#define _force_inline inline
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_heap_magic(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif
