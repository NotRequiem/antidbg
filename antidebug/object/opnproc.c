#include "opnproc.h"
#include "..\core\syscall.h"

typedef DWORD(__stdcall* TCsrGetProcessId)(void);

// technique can false flag if process legitimately acquires SeDebugPrivilege in older windows versions?
bool __adbg_open_process()
{
    // prevents DLL search order hijacking (CWE-427)
    const HMODULE ntdll = LoadLibraryEx(_T("ntdll.dll"), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!ntdll)
    {
        return false;
    }

    TCsrGetProcessId pfn_csr_get_process_id = (TCsrGetProcessId)GetProcAddress(ntdll, "CsrGetProcessId"); // not using our __get_module function on purpose
    if (!pfn_csr_get_process_id)
    {
        FreeLibrary(ntdll);
        return false;
    }

    HANDLE csr_handle = OpenProcess(((0x000F0000L) | (0x00100000L) | 0xFFFF), FALSE, pfn_csr_get_process_id());
    if (csr_handle != NULL)
    {
        DbgNtClose(csr_handle);
        FreeLibrary(ntdll);
        return true;
    }
    else
    {
        FreeLibrary(ntdll);
    }

    // syscall part
    csr_handle = NULL;
    OBJECT_ATTRIBUTES object_attributes = { 0 };
    InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);

    CLIENT_ID client_id = { 0 };
    client_id.UniqueProcess = (HANDLE)(ULONG_PTR)pfn_csr_get_process_id();
    client_id.UniqueThread = 0;

    ACCESS_MASK access = PROCESS_ALL_ACCESS;

    const NTSTATUS status = DbgNtOpenProcess(&csr_handle, access, &object_attributes, &client_id);

    if (NT_SUCCESS(status) && csr_handle != NULL)
    {
        DbgNtClose(csr_handle);
        return true;
    }
    else
    {
        return false;
    }
}