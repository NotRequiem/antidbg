#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <winternl.h>
#include <stdbool.h>

#include "..\adbg.h"

	bool CheckPEB();

#ifdef __cplusplus
}
#endif
