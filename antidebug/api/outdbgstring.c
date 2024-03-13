#include "outdbgstring.h"

bool CheckOutputDebugString()
{

	BOOL IsDbgPresent = FALSE;
	DWORD Val = 0x29A;

	if (IsWindowsXPOr2k())
	{
		SetLastError(Val);
		OutputDebugString(_T("test"));

		if (GetLastError() == Val)
			IsDbgPresent = TRUE;
	}

	return IsDbgPresent;
}

