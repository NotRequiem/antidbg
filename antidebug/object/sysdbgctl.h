#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>

#define SYSDBG_COMMAND 20

    typedef NTSTATUS(NTAPI* PFN_NtSystemDebugControl)(
        ULONG Command,
        PVOID InputBuffer,
        ULONG_PTR InputBufferLength,
        PVOID OutputBuffer,
        ULONG_PTR OutputBufferLength,
        PULONG ReturnLength
        );

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
