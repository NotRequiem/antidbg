// In development

#include <Windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include <stdbool.h>
#include <stdio.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define ProcessDebugFlags 7

typedef struct _RTL_DEBUG_INFORMATION {
    HANDLE SectionHandle;
    PVOID  SectionBase;
    PVOID  RemoteSectionBase;
    ULONG  SectionBaseDelta;
    HANDLE EventPairHandle;
    ULONG  Unknown[2];
    HANDLE RemoteThreadHandle;
    ULONG  InfoClassMask;
    ULONG  SizeOfInfo;
    ULONG  AllocatedSize;
    ULONG  SectionSize;
    PVOID  ModuleInformation;
    PVOID  BackTraceInformation;
    PVOID  HeapInformation;
    PVOID  LockInformation;
    PVOID  Reserved[8];
} RTL_DEBUG_INFORMATION, * PRTL_DEBUG_INFORMATION;

typedef NTSTATUS(NTAPI* PNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );

bool IsDebuggerPresentt() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        PNtQueryInformationProcess pfnNtQueryInformationProcess =
            (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            const ULONG bufferSize = sizeof(RTL_DEBUG_INFORMATION);
            PRTL_DEBUG_INFORMATION buffer = (PRTL_DEBUG_INFORMATION)malloc(bufferSize);
            if (buffer)
            {
                DWORD dwProcessDebugFlags = 0;  // Initialize to a known value
                ULONG dwReturned;
                NTSTATUS status = pfnNtQueryInformationProcess(
                    GetCurrentProcess(),
                    ProcessDebugFlags,
                    buffer,
                    bufferSize,
                    &dwReturned);

                if (status == STATUS_SUCCESS)
                {
                    if (dwReturned > bufferSize)
                    {
                        // The buffer overflowed; allocate a larger buffer
                        free(buffer);
                        buffer = (PRTL_DEBUG_INFORMATION)malloc(dwReturned);
                        if (!buffer)
                        {
                            printf("Error: Failed to allocate memory for the buffer.\n");
                            return false;
                        }

                        status = pfnNtQueryInformationProcess(
                            GetCurrentProcess(),
                            ProcessDebugFlags,
                            buffer,
                            dwReturned,
                            &dwReturned);
                    }

                    if (NT_SUCCESS(status) && (0 == dwProcessDebugFlags))
                    {
                        free(buffer);
                        FreeLibrary(hNtdll);
                        return true;  // Debugger is present
                    }
                    else if (!NT_SUCCESS(status))
                    {
                        printf("Error: NtQueryInformationProcess failed with status 0x%08X.\n", status);
                    }
                }
                else
                {
                    printf("Error: NtQueryInformationProcess failed with status 0x%08X.\n", status);
                }

                free(buffer);
            }
            else
            {
                printf("Error: Failed to allocate memory for the buffer.\n");
            }
        }
        else
        {
            FreeLibrary(hNtdll);
            printf("Error: GetProcAddress failed.\n");
        }
    }
    else
    {
        printf("Error: LoadLibraryA failed to load ntdll.dll.\n");
    }

    return false;
}

int main() {
    if (IsDebuggerPresentt())
    {
        printf("A debugger is present.\n");
    }
    else
    {
        printf("No debugger detected.\n");
    }

    return 0;
}
