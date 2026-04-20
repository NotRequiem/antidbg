#pragma once

#include <windows.h>
#include <stdbool.h>

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INVALID_INFO_CLASS
    #define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
    #define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct _CALLBACK_PAGE {
        PVOID  base;
        SIZE_T size;
    } CALLBACK_PAGE;

    extern CALLBACK_PAGE g_callback_page;

    bool __set_callback(CALLBACK_PAGE* outPage, HANDLE process_handle);

    bool __detect_callback(PVOID callback_page, SIZE_T page_size, HANDLE process_handle);

#ifdef __cplusplus
}
#endif