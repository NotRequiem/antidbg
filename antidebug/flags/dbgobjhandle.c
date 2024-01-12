#include "dbgobjhandle.h"

bool IsDebuggerPresent_DebugObjectHandle() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        TNtQueryInformationProcess pfnNtQueryInformationProcess =
            (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            HANDLE hProcessDebugObject = 0;
            const DWORD ProcessDebugObjectHandle = 0x1e;
            DWORD dwReturned;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugObjectHandle,
                &hProcessDebugObject,
                sizeof(HANDLE),
                &dwReturned);

            FreeLibrary(hNtdll);

            return NT_SUCCESS(status) && (hProcessDebugObject != 0);
        }
        else
        {
            FreeLibrary(hNtdll);
            printf("Error: GetProcAddress failed to retrieve NtQueryInformationProcess.\n");
        }
    }
    else
    {
        printf("Error: LoadLibraryA failed to load ntdll.dll.\n");
    }

    return false;
}