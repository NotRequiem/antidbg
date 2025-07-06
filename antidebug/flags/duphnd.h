#pragma once

#include <windows.h>
#include <stdbool.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool DuplicatedHandles(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif

