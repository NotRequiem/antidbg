#pragma once

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool StartAttachProtection(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif