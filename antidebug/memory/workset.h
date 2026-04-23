#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
	#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// MemoryInformationClass value for MemoryWorkingSetList
#define MemoryWorkingSetList 1

#ifdef __cplusplus
extern "C" {
#endif

    typedef union _PSAPI_WORKING_SET_BLOCK_64 {
        ULONG64 Flags;
        struct {
            ULONG64 Protection : 5;
            ULONG64 ShareCount : 3;
            ULONG64 Shared : 1;
            ULONG64 Reserved : 3;
            ULONG64 VirtualPage : 52;
        };
    } PSAPI_WORKING_SET_BLOCK_64, * PPSAPI_WORKING_SET_BLOCK_64;

    typedef struct _MEMORY_WORKING_SET_LIST_64
    {
        ULONG64 NumberOfPages;
        PSAPI_WORKING_SET_BLOCK_64 WorkingSetList[1];
    } MEMORY_WORKING_SET_LIST_64, * PMEMORY_WORKING_SET_LIST_64;

    bool __adbg_working_set(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif
