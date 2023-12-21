#include "opnproc.h"

typedef DWORD(WINAPI* TCsrGetProcessId)(VOID);

bool CheckOpenProcess()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
    {
        fprintf(stderr, "Failed to load ntdll.dll\n");
        return false;
    }

    TCsrGetProcessId pfnCsrGetProcessId = (TCsrGetProcessId)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pfnCsrGetProcessId)
    {
        fprintf(stderr, "Failed to get CsrGetProcessId function address\n");
        FreeLibrary(hNtdll);
        return false;
    }

    HANDLE hCsr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pfnCsrGetProcessId());
    if (hCsr != NULL)
    {
        CloseHandle(hCsr);
        FreeLibrary(hNtdll);
        return true;
    }
    else
    {
        FreeLibrary(hNtdll);
        return false;
    }
}