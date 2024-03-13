#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>

	BOOL bIsBeinDbg = TRUE;

	static LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers)
	{
		bIsBeinDbg = FALSE;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	bool CheckUnhandledExcepFilter();

#ifdef __cplusplus
}
#endif