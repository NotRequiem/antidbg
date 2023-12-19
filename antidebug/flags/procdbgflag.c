#include "procdbgflag.h"

bool IsDebuggerPresent_DebugFlags() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        TNtQueryInformationProcess pfnNtQueryInformationProcess =
            (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            DWORD dwProcessDebugFlags, dwReturned;
            const DWORD ProcessDebugFlags = 0x1f;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugFlags,
                &dwProcessDebugFlags,
                sizeof(DWORD),
                &dwReturned);

            FreeLibrary(hNtdll);

            return NT_SUCCESS(status) && (0 == dwProcessDebugFlags);
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