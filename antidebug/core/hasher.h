#pragma once

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>
#include <stdbool.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#pragma comment(lib, "psapi.lib")

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        HMODULE hMod;
        DWORD   textRVA;
        DWORD   textSize;
        uint32_t originalCrc;
    } ModuleCRC;

	void StartMemoryTracker(const HANDLE hProcess);

#ifdef __cplusplus
}
#endif