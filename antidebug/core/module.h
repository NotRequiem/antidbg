#pragma once

#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>

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

	void* __get_module(const char* module_name, const char* function_name);

#ifdef __cplusplus
}
#endif