#include "sysdbgcontrol.h"
#include "..\core\syscall.h"

static inline bool _enable_privilege(const HANDLE process_handle)
{
    HANDLE token_handle = NULL;
    NTSTATUS status;

    status = DbgNtOpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle);
    if (!NT_SUCCESS(status))
    {
        return false;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    status = DbgNtAdjustPrivilegesToken(token_handle, FALSE, &tp, sizeof(tp), NULL, NULL);

    DbgNtClose(token_handle);

    return NT_SUCCESS(status);
}

static inline void _disable_privilege(const HANDLE process_handle)
{
    HANDLE token_handle = NULL;

    DbgNtOpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle);

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = 0;

    DbgNtAdjustPrivilegesToken(token_handle, FALSE, &tp, sizeof(tp), NULL, NULL);

    DbgNtClose(token_handle);
}

static inline bool __adbg_is_admin(const HANDLE process_handle)
{
    HANDLE token_handle = NULL;
    NTSTATUS status;

    status = DbgNtOpenProcessToken(process_handle, TOKEN_QUERY, &token_handle);
    if (!NT_SUCCESS(status))
    {
        return false;
    }

    TOKEN_ELEVATION elevation = { 0 };
    ULONG return_length = 0;

    status = DbgNtQueryInformationToken(
        token_handle,
        TokenElevation,
        &elevation,
        sizeof(elevation),
        &return_length
    );

    DbgNtClose(token_handle);

    return NT_SUCCESS(status) && (elevation.TokenIsElevated != 0);
}

bool __adbg_system_debug_control(const HANDLE process_handle)
{
    if (!_enable_privilege(process_handle) || !__adbg_is_admin(process_handle)) {
        return false;
    }

    volatile UCHAR output_buffer[1024] = { 0 };
    for (size_t i = 0; i < sizeof(output_buffer); i++) {
        ((UCHAR*)output_buffer)[i] = 0xAA;
    }

    ULONG return_length = 0;

    NTSTATUS status = DbgNtSystemDebugControl(
        SysDbgGetTriageDump,
        NULL,
        0,
        (PVOID)output_buffer,
        sizeof(output_buffer),
        &return_length
    );

    _disable_privilege(process_handle);

    // if a debugger blocks this specific command
    if (status == STATUS_ACCESS_DENIED) {
        return true;
    }

    // check if they actually touched the buffer
    if (NT_SUCCESS(status)) {
        const volatile UCHAR* buf = output_buffer;

        for (size_t i = 0; i < sizeof(output_buffer); i++) {
            if (buf[i] != 0xAA) {
                return false;  
            }
        }

        return true;           
    }

    return false;
}