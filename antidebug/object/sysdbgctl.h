#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>

    typedef NTSTATUS(NTAPI* PFN_NtSystemDebugControl)(SYSDBG_COMMAND, PVOID, ULONG_PTR);

    static PFN_NtSystemDebugControl GetNtSystemDebugControlPointer() {
        HMODULE hNtdll = LoadLibrary("ntdll.dll");
        if (hNtdll == NULL) {
            printf("Failed to load ntdll.dll\n");
            return NULL;
        }

        PFN_NtSystemDebugControl pfnNtSystemDebugControl = (PFN_NtSystemDebugControl)GetProcAddress(hNtdll, "NtSystemDebugControl");
        if (pfnNtSystemDebugControl == NULL) {
            printf("Failed to get address of NtSystemDebugControl function\n");
            FreeLibrary(hNtdll);
            return NULL;
        }

        return pfnNtSystemDebugControl;
    }

    bool NtSystemDebugControl();

#ifdef __cplusplus
}
#endif

