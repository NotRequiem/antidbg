#include "mapview.h"
#include "..\core\syscall.h"

bool __adbg_freeze_debugger(const HANDLE process_handle)
{
    HANDLE section_handle = NULL;
    PVOID view_base_address = NULL;
    LARGE_INTEGER maximum_size = { 0 };
    SIZE_T view_size;
    NTSTATUS status;

    maximum_size.QuadPart = (LONGLONG)VIEW_SIZE_12_TIB;
    view_size = (SIZE_T)VIEW_SIZE_12_TIB;

    status = DbgNtCreateSection(
        &section_handle,
        SECTION_MAP_READ |
        SECTION_MAP_WRITE |
        SECTION_QUERY,
        NULL,
        &maximum_size,
        PAGE_READWRITE,
        SEC_RESERVE,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = DbgNtMapViewOfSection(
        section_handle,
        process_handle,
        &view_base_address,
        0,
        0x1000,
        NULL,
        &view_size,
        ViewUnmap,
        MEM_RESERVE,
        PAGE_READWRITE       
    );

    DbgNtClose(section_handle);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    return TRUE;
}
