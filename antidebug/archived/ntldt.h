#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

    bool __adbg_ldt_entries(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif