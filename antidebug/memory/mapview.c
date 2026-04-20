#include "mapview.h"
#include "..\core\syscall.h"

bool __adbg_freeze_debugger(const HANDLE process_handle)
{
    HANDLE section_handle = NULL;
    PVOID  view_base_address = NULL;
    SIZE_T region_size = (12ull << 40);
    NTSTATUS nt_status_code;

    nt_status_code = DbgNtCreateSection(
        &section_handle,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        INVALID_HANDLE_VALUE
    );

    if (nt_status_code < 0) {
        return false;
    }

    nt_status_code = DbgNtMapViewOfSection(
        section_handle,
        process_handle,
        &view_base_address,
        0,
        0,
        NULL,
        &region_size,
        ViewUnmap,
        0x2000,
        PAGE_READWRITE
    );

    if (section_handle) DbgNtClose(section_handle);
    return (nt_status_code >= 0) ? true : false;
}