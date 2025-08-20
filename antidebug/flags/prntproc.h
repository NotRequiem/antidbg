#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool ParentProcesses(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif