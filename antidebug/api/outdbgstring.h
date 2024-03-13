#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <tchar.h>

#define VERSIONHELPERAPI inline bool

	VERSIONHELPERAPI
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

	VERSIONHELPERAPI
		IsWindowsXPOr2k()
	{
		return IsWindowsVersionOrLesser(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0);
	}

	bool CheckOutputDebugString();

#ifdef __cplusplus
}
#endif
