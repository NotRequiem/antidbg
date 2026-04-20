#include "sysdbgcontrol.h"
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

static void _disable_privilege(const HANDLE process_handle)
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

bool __adbg_system_debug_control(const HANDLE process_handle)
{
    if (!_enable_privilege(process_handle)) {
        return false;
    }

    UCHAR output_buffer[1024] = { 0 };
    const UCHAR MAGIC_PATTERN = 0xAA;

    // memset
    for (size_t i = 0; i < sizeof(output_buffer); i++)
    {
        output_buffer[i] = MAGIC_PATTERN;
    }

    ULONG return_length = 0;

    const NTSTATUS status = DbgNtSystemDebugControl(
        SysDbgGetTriageDump,
        NULL,                 
        0,                    
        output_buffer,         
        sizeof(output_buffer),  
        &return_length         
    );

    _disable_privilege(process_handle);

    // if a debugger blocks this specific command
    if (status == STATUS_ACCESS_DENIED)
    {
        return true;
    }

    // check if the output buffer was actually touched
    if (NT_SUCCESS(status))
    {
        bool was_modified = false;

        for (size_t i = 0; i < sizeof(output_buffer); i++)
        {
            if (output_buffer[i] != MAGIC_PATTERN)
            {
                was_modified = true;
                break;
            }
        }

        if (!was_modified) {
            return true;
        }
    }

    return false;
}