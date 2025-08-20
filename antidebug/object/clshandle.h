#pragma once

#include <windows.h>
#include <stdbool.h>
#include <tchar.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE);

	bool CheckCloseHandle();

#ifdef __cplusplus
}
#endif
