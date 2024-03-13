#include "unhexcp.h"

BOOL bIsBeinDbg = TRUE;

static LONG WINAPI UnhandledExcepFilter(PEXCEPTION_POINTERS pExcepPointers)
{
	bIsBeinDbg = FALSE;
	return EXCEPTION_CONTINUE_EXECUTION;
}

bool CheckUnhandledExcepFilter()
{
	LPTOP_LEVEL_EXCEPTION_FILTER Top = SetUnhandledExceptionFilter(UnhandledExcepFilter);
	RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL);
	SetUnhandledExceptionFilter(Top);
	return bIsBeinDbg;
}
