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

	BOOL IsDbgPresent = FALSE;
	DWORD Val = 0x29A;

	if (IsWindowsXPOr2k())
	{
		SetLastError(Val);
		OutputDebugString(_T("x"));

		if (GetLastError() == Val)
			IsDbgPresent = TRUE;
	}

	return IsDbgPresent;
}

