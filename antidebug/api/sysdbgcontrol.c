#include "sysdbgcontrol.h"
#include "..\core\syscall.h"

static inline bool _enable_privilege(const HANDLE process_handle, PTOKEN_PRIVILEGES old_tp)
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

    ULONG return_length = 0;
    status = DbgNtAdjustPrivilegesToken(token_handle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), old_tp, &return_length);

    DbgNtClose(token_handle);

    return NT_SUCCESS(status);
}

static inline void _restore_privilege(const HANDLE process_handle, PTOKEN_PRIVILEGES old_tp)
{
    HANDLE token_handle = NULL;
    if (NT_SUCCESS(DbgNtOpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)))
    {
        DbgNtAdjustPrivilegesToken(token_handle, FALSE, old_tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        DbgNtClose(token_handle);
    }
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
    TOKEN_PRIVILEGES old_tp = { 0 };

    if (!_enable_privilege(process_handle, &old_tp) || !__adbg_is_admin(process_handle)) {
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

    _restore_privilege(process_handle, &old_tp);

    if (status == STATUS_ACCESS_DENIED) {
        return true;
    }

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