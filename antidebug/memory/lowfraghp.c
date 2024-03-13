#include "lowfraghp.h"

static BOOL IsWindowsVista() {
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

static BOOL IsWindows7() {
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

static BOOL IsWindows8or8PointOne() {
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

bool LowFragmentationHeap()
{
	PINT_PTR FrontEndHeap = NULL;

	HANDLE hHeap = GetProcessHeap();

	if (IsWindowsVista() || IsWindows7()) {
#if defined (ENV64BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0x178);

#elif defined(ENV32BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0xd4);
#endif
	}

	if (IsWindows8or8PointOne()) {
#if defined (ENV64BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0x170);

#elif defined(ENV32BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0xd0);
#endif
	}

	if (FrontEndHeap && *FrontEndHeap == 0) {
		return TRUE;
	}

	return FALSE;
}
