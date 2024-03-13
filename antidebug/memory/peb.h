#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <winternl.h>
#include <stdbool.h>

	bool CheckPEB();

#ifdef __cplusplus
}
#endif
