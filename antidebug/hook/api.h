#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <psapi.h>
#include <string.h>

	bool CheckModuleBounds();

#ifdef __cplusplus
}
#endif
