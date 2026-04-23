#pragma once

#include <windows.h>
#include <stdbool.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef NTSTATUS(__stdcall* pfn_nt_close)(HANDLE);

	bool __adbg_close_handle();

#ifdef __cplusplus
}
#endif
