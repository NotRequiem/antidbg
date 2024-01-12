#include <Windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <winternl.h>

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

    // Use NT_SUCCESS macro to check the status
    return NT_SUCCESS(pNtSetDebugFilterState(0, 0, TRUE));
}
