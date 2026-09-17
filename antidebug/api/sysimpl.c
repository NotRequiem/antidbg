#include "sysimpl.h"
#include "..\core\syscall.h"

typedef struct _system_kernel_debugger_info {
    BOOLEAN debugger_enabled;
    BOOLEAN debugger_not_present;
} system_kernel_debugger_info, * psystem_kernel_debugger_info;

typedef struct _system_code_integrity_info {
    ULONG length;
    ULONG code_integrity_options;
} system_code_integrity_info, * psystem_code_integrity_info;

typedef struct _system_boot_environment_info {
    GUID boot_identifier;
    ULONG firmware_type;
    ULONG64 boot_flags;
} system_boot_environment_info, * psystem_boot_environment_info;

typedef NTSTATUS(__stdcall* pfn_nt_query_system_information)(
    ULONG system_information_class,
    PVOID system_information,
    ULONG system_information_length,
    PULONG return_length
);

typedef NTSTATUS(__stdcall* pfn_nt_create_debug_object)(
    OUT PHANDLE debug_object_handle,
    IN ACCESS_MASK desired_access,
    IN POBJECT_ATTRIBUTES object_attributes,
    IN ULONG flags
);

bool __adbg_check_syscalls()
{
    HMODULE h_ntdll = GetModuleHandleA("ntdll.dll");
    if (!h_ntdll)
        return false;

    pfn_nt_create_debug_object p_nt_create_debug_object =
        (pfn_nt_create_debug_object)GetProcAddress(h_ntdll, "NtCreateDebugObject");

    if (p_nt_create_debug_object)
    {
        HANDLE h_debug = NULL;
        OBJECT_ATTRIBUTES object_attributes = { 0 };
        InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);

        NTSTATUS status = p_nt_create_debug_object(
            &h_debug,
            0x001F000F,
            &object_attributes,
            0
        );

        if (status == STATUS_NOT_IMPLEMENTED)
        {
            return true;
        }

        if (NT_SUCCESS(status) && h_debug != NULL)
        {
            CloseHandle(h_debug);
        }
    }

    pfn_nt_query_system_information p_nt_query_system_information =
        (pfn_nt_query_system_information)GetProcAddress(
            h_ntdll,
            "NtQuerySystemInformation"
        );

    if (p_nt_query_system_information)
    {
        system_code_integrity_info code_integrity_info = { 0 };
        code_integrity_info.length = sizeof(code_integrity_info);
        ULONG return_length = 0;

        NTSTATUS status = p_nt_query_system_information(
            SystemCodeIntegrityInformationClass,
            &code_integrity_info,
            sizeof(code_integrity_info),
            &return_length
        );

        if (status == STATUS_NOT_IMPLEMENTED)
        {
            return true;
        }

        system_boot_environment_info boot_info = { 0 };
        status = p_nt_query_system_information(
            SystemBootEnvironmentInformationClass,
            &boot_info,
            sizeof(boot_info),
            &return_length
        );

        if (status == STATUS_NOT_IMPLEMENTED)
        {
            return true;
        }
    }

    return false;
}
