#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>

// Function to check if the program is being debugged
bool MemoryBreakpoint();

#ifdef __cplusplus
}
#endif
