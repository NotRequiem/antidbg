#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>

	BOOL IsWindowsVista() {
		OSVERSIONINFOEX osvi;
		DWORDLONG dwlConditionMask = 0;
		int op = VER_EQUAL;

		ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		osvi.dwMajorVersion = 6;
		osvi.dwMinorVersion = 0;

		VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, op);
		VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, op);

		return VerifyVersionInfo(
			&osvi,
			VER_MAJORVERSION | VER_MINORVERSION,
			dwlConditionMask);
	}

	BOOL IsWindows7() {
		OSVERSIONINFOEX osvi;
		DWORDLONG dwlConditionMask = 0;
		int op = VER_EQUAL;

		ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		osvi.dwMajorVersion = 6;
		osvi.dwMinorVersion = 1;

		VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, op);
		VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, op);

		return VerifyVersionInfo(
			&osvi,
			VER_MAJORVERSION | VER_MINORVERSION,
			dwlConditionMask);
	}

	BOOL IsWindows8or8PointOne() {
		OSVERSIONINFOEX osvi;
		DWORDLONG dwlConditionMask = 0;
		int MajorOp = VER_EQUAL;
		int MinorOp = VER_GREATER_EQUAL;

		ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		osvi.dwMajorVersion = 6;
		osvi.dwMinorVersion = 2;

		VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, MajorOp);
		VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, MinorOp);

		return VerifyVersionInfo(
			&osvi,
			VER_MAJORVERSION | VER_MINORVERSION,
			dwlConditionMask);
	}

	bool LowFragmentationHeap();

#ifdef __cplusplus
}
#endif