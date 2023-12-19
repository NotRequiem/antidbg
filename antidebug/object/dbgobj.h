#pragma once

#include <windows.h>
#include <winternl.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfHandles;
    ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION {
    ULONG NumberOfObjects;
    OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;

typedef NTSTATUS(WINAPI* TNtQueryObject)(
    HANDLE                   Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID                    ObjectInformation,
    ULONG                    ObjectInformationLength,
    PULONG                   ReturnLength
    );

enum { ObjectAllTypesInformation = 3 };
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

bool CheckNtQueryObject();

#ifdef __cplusplus
}
#endif
