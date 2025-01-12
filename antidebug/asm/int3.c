#include "int3.h"

static BOOL SwallowedException = TRUE;

static LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	SwallowedException = FALSE;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		ExceptionInfo->ContextRecord->Rip++;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL __try_interrupt()
{
	PVOID Handle = AddVectoredExceptionHandler(1, VectoredHandler);
	SwallowedException = TRUE;
	__debugbreak();
	RemoveVectoredExceptionHandler(Handle);
	return SwallowedException;
}

bool g_bDebugged = false;

static inline int filter(unsigned int code)
{
	g_bDebugged = code != EXCEPTION_BREAKPOINT;
	return EXCEPTION_EXECUTE_HANDLER;
}

bool int3()
{
	__try_interrupt();

	bool result = false;
	__try
	{
		__debugbreak();
	}
	__except (filter(GetExceptionCode()))
	{
		result = g_bDebugged;
	}
	return result;
}