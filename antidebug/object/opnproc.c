#include "opnproc.h"
#include "..\core\syscall.h"

typedef DWORD(__stdcall* TCsrGetProcessId)(void);

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

    HANDLE hCsr = OpenProcess(((0x000F0000L) | (0x00100000L) | 0xFFFF), FALSE, pfnCsrGetProcessId());
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