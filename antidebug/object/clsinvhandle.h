#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>

    typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE);

    static PFN_NtClose GetNtClosePointer() {
        HMODULE hNtdll = LoadLibrary("ntdll.dll");
        if (hNtdll == NULL) {
            printf("Failed to load ntdll.dll\n");
            return NULL;
        }

        PFN_NtClose pfnNtClose = (PFN_NtClose)GetProcAddress(hNtdll, "NtClose");
        if (pfnNtClose == NULL) {
            printf("Failed to get address of NtClose function\n");
            FreeLibrary(hNtdll);
            return NULL;
        }

        return pfnNtClose;
        }

    static BOOL NtClose_InvalideHandle()
    {
        PFN_NtClose NtClose_ = GetNtClosePointer();
        if (NtClose_ == NULL) {
            printf("Failed to get pointer for NtClose\n");
            return FALSE;
        }

        __try {
            NtClose_((HANDLE)0x99999999ULL);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return TRUE;
        }

        return FALSE;
    }

    bool CloseInvalidHandle();

#ifdef __cplusplus
}
#endif