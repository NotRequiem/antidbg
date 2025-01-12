#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool StackSegmentRegister(const HANDLE hThread);

#ifdef __cplusplus
}
#endif
