#pragma once

#include <windows.h>
#include <stdbool.h>

#define UNUSED(x) ((void)(x))

#ifdef __cplusplus
extern "C" {
#endif

	bool __adbg_timing_attack();

#ifdef __cplusplus
}
#endif