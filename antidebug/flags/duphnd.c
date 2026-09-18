#include "duphnd.h"
#include "..\core\module.h"

typedef enum _CUSTOM_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    ObjectSessionObjectInformation,
    MaxObjectInfoClass
} CUSTOM_OBJECT_INFORMATION_CLASS;

typedef struct _CUSTOM_HANDLE_FLAG_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} CUSTOM_HANDLE_FLAG_INFORMATION, * PCUSTOM_HANDLE_FLAG_INFORMATION;

typedef NTSTATUS(__stdcall* nt_set_information_object)(
    _In_ HANDLE Handle,
    _In_ CUSTOM_OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _In_ PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength
);

// not syscalled on purpose
bool __adbg_duplicate_handles(const HANDLE process_handle)
{
    nt_set_information_object pfn_nt_set_information_object = (nt_set_information_object)__get_module("ntdll.dll", "ZwSetInformationObject");
    if (!pfn_nt_set_information_object) return false;

    CUSTOM_HANDLE_FLAG_INFORMATION flags_on = { FALSE, TRUE };
    CUSTOM_HANDLE_FLAG_INFORMATION flags_off = { FALSE, FALSE };

    HANDLE dup1 = NULL;
    bool debugged = false;

    if (DuplicateHandle(process_handle, process_handle, process_handle, &dup1, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        pfn_nt_set_information_object(dup1, ObjectHandleFlagInformation, &flags_on, sizeof(flags_on));

        bool was_closed = false;

        __try {
            if (CloseHandle(dup1)) {
                was_closed = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            debugged = true;
        }

        if (!was_closed) {
            pfn_nt_set_information_object(dup1, ObjectHandleFlagInformation, &flags_off, sizeof(flags_off));
            CloseHandle(dup1);
        }
        else {
            debugged = true;
        }
    }

    return debugged;
}