#include "opnproc.h"
#include "..\core\syscall.h"

typedef DWORD(__stdcall* TCsrGetProcessId)(void);

bool CheckOpenProcess()
{
    HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
    if (!hNtdll)
    {
        return false;
    }

    TCsrGetProcessId pfnCsrGetProcessId = (TCsrGetProcessId)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pfnCsrGetProcessId)
    {
        FreeLibrary(hNtdll);
        return false;
    }

    const HANDLE hCsr = OpenProcess(((0x000F0000L) | (0x00100000L) | 0xFFFF), FALSE, pfnCsrGetProcessId());
    if (hCsr != NULL)
    {
        DbgNtClose(hCsr);
        FreeLibrary(hNtdll);
        return true;
    }
    else
    {
        FreeLibrary(hNtdll);
        return false;
    }
}