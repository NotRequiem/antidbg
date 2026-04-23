#include "setdbgfltstate.h"
#include "..\core\syscall.h"

static bool _enable_privilege(const HANDLE process_handle)
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

static inline bool _disable_privilege(const HANDLE process_handle)
{
    HANDLE token_handle = NULL;

    NTSTATUS status = DbgNtOpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle);
    if (!NT_SUCCESS(status))
    {
        return false;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = 0; 

    status = DbgNtAdjustPrivilegesToken(token_handle, FALSE, &tp, sizeof(tp), NULL, NULL);

    DbgNtClose(token_handle);

    return NT_SUCCESS(status);
}

bool __adbg_filter_state(const HANDLE process_handle)
{
    bool debugged = false;
    NTSTATUS status;

    if (!_disable_privilege(process_handle))
    {
        return false;
    }

    // ComponentId = 0 (Kd_Default_Mask), Level = 0, State = TRUE
    status = DbgNtSetDebugFilterState(0, 0, TRUE);

    if (status == STATUS_SUCCESS)
    {
        debugged = true;
    }

    if (_enable_privilege(process_handle))
    {
        status = DbgNtSetDebugFilterState(0, 0, TRUE);

        if (status == STATUS_ACCESS_DENIED)
        {
            debugged = true;
        }

        _disable_privilege(process_handle);
    }

    return debugged;
}