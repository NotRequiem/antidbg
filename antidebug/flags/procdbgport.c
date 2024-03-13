#include "procdbgport.h"

bool CheckNtQueryInformationProcess() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        TNtQueryInformationProcess pfnNtQueryInformationProcess =
            (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugPort = 0, dwReturned;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &dwProcessDebugPort,
                sizeof(DWORD),
                &dwReturned);

            FreeLibrary(hNtdll);

            return NT_SUCCESS(status) && (-1 == (int)dwProcessDebugPort);
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
