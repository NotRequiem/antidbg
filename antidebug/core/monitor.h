#pragma once

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <intrin.h>
#include <stdint.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

#define SystemTimeSlipInformation 0x2E

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SEC_IMAGE
    #define SEC_IMAGE 0x1000000
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
    #define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

#ifndef OBJ_CASE_INSENSITIVE
    #define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#if defined(__clang__) || defined(__GNUC__)
    #define _force_inline __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
    #define _force_inline __forceinline
#else
    #define _force_inline inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        HMODULE module_handle;
        DWORD   text_rva;
        DWORD   text_size;
        uint32_t original_crc;
    } module_crc;

	void __start_monitor(const HANDLE process_handle);

#ifdef __cplusplus
}
#endif