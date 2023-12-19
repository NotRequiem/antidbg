#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdbool.h>

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

bool CheckNtQueryInformationProcess();

#ifdef __cplusplus
}
#endif
