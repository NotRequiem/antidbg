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

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_heap_magic();

#ifdef __cplusplus
}
#endif
