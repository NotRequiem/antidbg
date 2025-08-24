#include "opnproc.h"
#include "..\core\syscall.h"

typedef DWORD(__stdcall* TCsrGetProcessId)(void);

bool CheckOpenProcess()
{
    // prevents DLL search order hijacking (CWE-427)
    const HMODULE hNtdll = LoadLibraryEx(_T("ntdll.dll"), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
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
    }

    // syscall part
    hCsr = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pfnCsrGetProcessId();
    clientId.UniqueThread = 0;

    ACCESS_MASK desiredAccess = PROCESS_ALL_ACCESS;

    const NTSTATUS status = DbgNtOpenProcess(&hCsr, desiredAccess, &objAttr, &clientId);

    if (NT_SUCCESS(status) && hCsr != NULL)
    {
        DbgNtClose(hCsr);
        return true;
    }
    else
    {
        return false;
    }
}