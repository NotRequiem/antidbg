#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdbool.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(WINAPI* pRtlQueryProcessDebugInformation)(
    _In_ HANDLE UniqueProcessId,
    _In_ ULONG Flags,
    _Inout_ PVOID Buffer
    );

typedef struct _RTL_HEAP_ENTRY {
    PVOID       PreviousBlockPrivateData;
    USHORT      Size;
    USHORT      Flags;
    USHORT      AllocatorBackTraceIndex;
    USHORT      Reserved;
} RTL_HEAP_ENTRY, * PRTL_HEAP_ENTRY;

typedef struct _RTL_HEAP_INFORMATION {
    PVOID           BaseAddress;
    ULONG           Flags;
    USHORT          EntryOverhead;
    USHORT          CreatorBackTraceIndex;
    SIZE_T          BytesAllocated;
    SIZE_T          BytesCommitted;
    ULONG           NumberOfBlocks;
    ULONG           NumberOfEntries;
    RTL_HEAP_ENTRY  Entries[1];  // Flexible array member
} RTL_HEAP_INFORMATION, * PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS {
    ULONG               NumberOfHeaps;
    RTL_HEAP_INFORMATION Heaps[1];  // Flexible array member
} RTL_PROCESS_HEAPS, * PRTL_PROCESS_HEAPS;

#define PDI_HEAPS           0x1
#define PDI_HEAP_BLOCKS     0x2

static bool Check() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        return false;
    }

    pRtlQueryProcessDebugInformation pRtlQueryProcessDebugInfo = (pRtlQueryProcessDebugInformation)GetProcAddress(hNtdll, "RtlQueryProcessDebugInformation");
    if (!pRtlQueryProcessDebugInfo) {
        return false;
    }

    HANDLE hProcess = GetCurrentProcess();
    ULONG flags = 0;

    SIZE_T bufferSize = sizeof(RTL_PROCESS_HEAPS);
    PRTL_PROCESS_HEAPS pProcessHeaps = (PRTL_PROCESS_HEAPS)malloc(bufferSize);
    if (!pProcessHeaps) {
        return false;
    }

    NTSTATUS status = pRtlQueryProcessDebugInfo(hProcess, PDI_HEAPS | PDI_HEAP_BLOCKS, pProcessHeaps);
    if (!NT_SUCCESS(status)) {
        free(pProcessHeaps);
        return false;
    }

    flags = pProcessHeaps->Heaps[0].Flags;

    free(pProcessHeaps);

    return !(flags & HEAP_GROWABLE);
}

int main() {
    if (Check()) {
        printf("Heap is not growable.\n");
    }
    else {
        printf("Heap is growable.\n");
    }

    return 0;
}
