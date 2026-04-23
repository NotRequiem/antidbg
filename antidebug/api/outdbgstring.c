#include "outdbgstring.h"

inline static BOOL
_check_win_ver(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
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

inline static BOOL
_is_windows_xp() // or 2K
{
	return _check_win_ver(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0);
}

bool __adbg_output_dbg_str()
{
	__try {
		OutputDebugString(TEXT("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { ; }

	BOOL debugged = FALSE;
	DWORD val = 0x29A;

	if (_is_windows_xp())
	{
		SetLastError(val);
		OutputDebugString(_T("x"));

		if (GetLastError() == val)
			debugged = TRUE;
	}

	const WCHAR output_string[] = L"xd";
	ULONG_PTR args[4] = { 0 };

	args[0] = (ULONG_PTR)(sizeof(output_string) / sizeof(output_string[0]));
	args[1] = (ULONG_PTR)output_string;
	__try
	{
		RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, 4, args);
		RaiseException(DBG_PRINTEXCEPTION_C, 0, 4, args);
		debugged = TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return debugged;
}
