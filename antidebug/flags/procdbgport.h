#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool CheckNtQueryInformationProcess(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif
