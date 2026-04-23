#include "clshandle.h"
#include "../core/syscall.h"

static inline pfn_nt_close _get_ntclose() 
{
    HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
    if (ntdll == NULL) {
        return NULL;
    }

    pfn_nt_close pfn_ntclose = (pfn_nt_close)GetProcAddress(ntdll, "NtClose"); // not using our __get_module function on purpose

    if (pfn_ntclose == NULL) {
        return NULL;
    }

    return pfn_ntclose;
}

static inline BOOL _close_handle()
{
    pfn_nt_close ntclose = _get_ntclose();
    if (ntclose == NULL) {
        return FALSE;
    }

    __try {
        ntclose((HANDLE)0x99999999ULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }

    __try {
        DbgNtClose((HANDLE)0x99999999ULL); // now try manual syscall
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }

    return FALSE;
}

bool __adbg_close_handle()
{
    __try {
        CloseHandle((HANDLE)0x99999999ULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }

    const DWORD ret = CloseWindow((HWND)0x1234);
    if (ret != 0 || GetLastError() != ERROR_INVALID_WINDOW_HANDLE)
    {
        return true;
    }

    if (_close_handle())
        return true;

    __try
    {
        CloseHandle((HANDLE)(uintptr_t)0xDEADBEEF);
        return false;
    }
    __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return true;
    }
}
