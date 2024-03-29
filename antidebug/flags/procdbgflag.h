#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdbool.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

bool IsDebuggerPresent_DebugFlags();

#ifdef __cplusplus
}
#endif
