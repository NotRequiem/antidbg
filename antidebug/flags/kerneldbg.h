#pragma once

#include <windows.h>
#include <stdbool.h>
#include <winternl.h>
#include <stdio.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

#ifdef __cplusplus
extern "C" {
#endif

enum SYSTEM_INFORMATION_CLASS {
    SystemKernelDebuggerInformation = 0x23
};

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

__kernel_entry NTSTATUS NTAPI NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

bool KernelDebugger();

#ifdef __cplusplus
}
#endif
