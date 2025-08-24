#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <tchar.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

	bool CheckOpenProcess();

#ifdef __cplusplus
}
#endif

