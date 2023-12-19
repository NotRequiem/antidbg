#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdbool.h>

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN DWORD            ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

bool IsDebuggerPresent_DebugObjectHandle();

#ifdef __cplusplus
}
#endif
