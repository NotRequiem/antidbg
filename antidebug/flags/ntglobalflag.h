#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10

#define FLG_HEAP_ENABLE_FREE_CHECK   0x20

#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

	bool NtGlobalFlag();

#ifdef __cplusplus
}
#endif