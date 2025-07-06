#pragma once

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#pragma comment(lib, "psapi.lib")

#ifdef __cplusplus
extern "C" {
#endif

	void StartMemoryTracker(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif