#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    bool __adbg_ice(const HANDLE thread_handle);

#ifdef __cplusplus
}
#endif
