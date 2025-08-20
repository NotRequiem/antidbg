#include "outdbgstring.h"

inline BOOL
IsWindowsVersionOrLesser(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, { 0 }, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
			0, VER_MAJORVERSION, VER_EQUAL),
		VER_MINORVERSION, VER_LESS_EQUAL);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask) != FALSE;
}

inline BOOL
IsWindowsXPOr2k()
{
	return IsWindowsVersionOrLesser(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0);
}

bool CheckOutputDebugString()
{
	__try {
		OutputDebugString(TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { ; }

	BOOL IsDbgPresent = FALSE;
	DWORD Val = 0x29A;

	if (IsWindowsXPOr2k())
	{
		SetLastError(Val);
		OutputDebugString(_T("x"));

		if (GetLastError() == Val)
			IsDbgPresent = TRUE;
	}

	WCHAR* outputString = L"xd";
	ULONG_PTR args[4] = { 0 };
	args[0] = (ULONG_PTR)wcslen(outputString) + 1;
	args[1] = (ULONG_PTR)outputString;
	__try
	{
		RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, 4, args);
		RaiseException(DBG_PRINTEXCEPTION_C, 0, 4, args);
		IsDbgPresent = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return IsDbgPresent;
}

