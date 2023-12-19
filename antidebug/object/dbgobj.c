#include "dbgobj.h"

bool CheckNtQueryObject()
{
    bool bDebugged = false;
    NTSTATUS status;
    LPVOID pMem = NULL;
    ULONG dwMemSize;
    POBJECT_ALL_INFORMATION pObjectAllInfo;
    PBYTE pObjInfoLocation;
    HMODULE hNtdll;
    TNtQueryObject pfnNtQueryObject;

    hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
    {
        printf("Failed to load ntdll.dll\n");
        return false;
    }

    pfnNtQueryObject = (TNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    if (!pfnNtQueryObject)
    {
        printf("Failed to get address of NtQueryObject\n");
        return false;
    }

    status = pfnNtQueryObject(
        NULL,
        (OBJECT_INFORMATION_CLASS)ObjectAllTypesInformation,
        &dwMemSize, sizeof(dwMemSize), &dwMemSize);
    if (STATUS_INFO_LENGTH_MISMATCH != status)
    {
        printf("NtQueryObject failed during size query with status 0x%X\n", status);
        goto NtQueryObject_Cleanup;
    }

    pMem = VirtualAlloc(NULL, dwMemSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pMem)
    {
        printf("VirtualAlloc failed\n");
        goto NtQueryObject_Cleanup;
    }

    status = pfnNtQueryObject(
        (HANDLE)-1,
        (OBJECT_INFORMATION_CLASS)ObjectAllTypesInformation,
        pMem, dwMemSize, &dwMemSize);
    if (!SUCCEEDED(status))
    {
        printf("NtQueryObject failed during data query with status 0x%X\n", status);
        goto NtQueryObject_Cleanup;
    }

    pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMem;

    pObjInfoLocation = (PBYTE)pObjectAllInfo->ObjectTypeInformation;
    for (UINT i = 0; i < pObjectAllInfo->NumberOfObjects; i++)
    {
        POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

        if (pObjectTypeInfo->TypeName.Buffer != NULL)
        {
            if (pObjectTypeInfo->TypeName.Length > 0 &&
                pObjectTypeInfo->TypeName.MaximumLength > 0 &&
                pObjectTypeInfo->TypeName.MaximumLength >= pObjectTypeInfo->TypeName.Length)
            {
                if (wcslen(pObjectTypeInfo->TypeName.Buffer) > 0)
                {
                    if (wcscmp(L"DebugObject", pObjectTypeInfo->TypeName.Buffer) == 0)
                    {
                        if (pObjectTypeInfo->TotalNumberOfObjects > 0)
                        {
                            bDebugged = true;
                            printf("Debugger detected!\n");
                        }
                        break;
                    }
                }
            }
        }

        // Move to the next entry if the buffer is not null
        if (pObjectTypeInfo->TypeName.Buffer != NULL)
        {
            pObjInfoLocation += sizeof(OBJECT_TYPE_INFORMATION) + pObjectTypeInfo->TypeName.MaximumLength;
        }

    }

NtQueryObject_Cleanup:
    if (pMem)
        VirtualFree(pMem, 0, MEM_RELEASE);

    return bDebugged;
}