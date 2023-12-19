#include <Windows.h>
#include <stdbool.h>
#include <stdio.h>

/* For kernel mode access only */

// Prototype for NtSetDebugFilterState
typedef NTSTATUS(WINAPI* NtSetDebugFilterState_t)(ULONG ComponentId, ULONG Level, BOOLEAN State);

bool CheckNtSetDebugFilterState()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return false;

    NtSetDebugFilterState_t pNtSetDebugFilterState = (NtSetDebugFilterState_t)GetProcAddress(ntdll, "NtSetDebugFilterState");
    if (!pNtSetDebugFilterState)
        return false;

    return NT_SUCCESS(pNtSetDebugFilterState(0, 0, TRUE));
}

int main()
{
    bool result = CheckNtSetDebugFilterState();

    if (result)
        printf("Kernel-mode debugger is present.\n");
    else
        printf("Kernel-mode debugger is not present.\n");

    return 0;
}
