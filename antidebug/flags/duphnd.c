#include "duphnd.h"

typedef enum _MYOBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    ObjectSessionObjectInformation,
    MaxObjectInfoClass
} MYOBJECT_INFORMATION_CLASS;

typedef struct _MYOBJECT_HANDLE_FLAG_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} MYOBJECT_HANDLE_FLAG_INFORMATION, * PMYOBJECT_HANDLE_FLAG_INFORMATION;

typedef NTSTATUS(WINAPI* fnNtSetInformationObject)(
    _In_ HANDLE Handle,
    _In_ MYOBJECT_INFORMATION_CLASS ObjectInformationClass,
    _In_ PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength
    );

bool DuplicatedHandles(const HANDLE hProcess) {
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (!hNtdll) {
        return false;
    }

    fnNtSetInformationObject pfnNtSetInformationObject =
        (fnNtSetInformationObject)GetProcAddress(hNtdll, "ZwSetInformationObject");
    if (!pfnNtSetInformationObject) {
        return false;
    }

    MYOBJECT_HANDLE_FLAG_INFORMATION flagsOn = { FALSE, TRUE };
    MYOBJECT_HANDLE_FLAG_INFORMATION flagsOff = { FALSE, FALSE };

    HANDLE hDup1 = NULL, hDup2 = NULL;
    bool   failed = false;

    __try {
        if (!DuplicateHandle(hProcess, hProcess, hProcess, &hDup1, 0, FALSE, 0)) {
            failed = true;
            __leave;
        }

        pfnNtSetInformationObject(
            hDup1,
            ObjectHandleFlagInformation,
            &flagsOn,
            sizeof(flagsOn)
        );

        if (!DuplicateHandle(hProcess, hDup1, hProcess, &hDup2, 0, FALSE, 0)) {
            failed = true;
            __leave;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        failed = true;
    }

    if (hDup2) {
        pfnNtSetInformationObject(
            hDup2,
            ObjectHandleFlagInformation,
            &flagsOff,
            sizeof(flagsOff)
        );
        CloseHandle(hDup2);
    }

    if (hDup1) {
        pfnNtSetInformationObject(
            hDup1,
            ObjectHandleFlagInformation,
            &flagsOff,
            sizeof(flagsOff)
        );
        CloseHandle(hDup1);
    }

    return failed;
}
