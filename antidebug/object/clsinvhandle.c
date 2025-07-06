#include "clsinvhandle.h"

typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE);

static inline PFN_NtClose GetNtClosePointer() {
    HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
    if (hNtdll == NULL) {
        return NULL;
    }

    PFN_NtClose pfnNtClose = (PFN_NtClose)GetProcAddress(hNtdll, "NtClose");
    if (pfnNtClose == NULL) {
        FreeLibrary(hNtdll);
        return NULL;
    }

    return pfnNtClose;
}

static inline BOOL NtClose_InvalideHandle()
{
    PFN_NtClose NtClose_ = GetNtClosePointer();
    if (NtClose_ == NULL) {
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

bool CloseInvalidHandle()
{
    __try {
        CloseHandle((HANDLE)0x99999999ULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }

    const DWORD ret = CloseWindow((HWND)0x1234);
    if (ret != 0 || GetLastError() != ERROR_INVALID_WINDOW_HANDLE)
    {
        return TRUE;
    }

    if (NtClose_InvalideHandle())
        return TRUE;
    else
        return FALSE;
}
