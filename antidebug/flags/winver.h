#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>
#include <stdbool.h>

#ifdef __cplusplus

#define VERSIONHELPERAPI inline bool

#else

#define VERSIONHELPERAPI FORCEINLINE BOOL

#endif 

    VERSIONHELPERAPI
    IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
    {
        OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
        DWORDLONG        const dwlConditionMask = VerSetConditionMask(
            VerSetConditionMask(
                VerSetConditionMask(
                    0, VER_MAJORVERSION, VER_GREATER_EQUAL),
                VER_MINORVERSION, VER_GREATER_EQUAL),
            VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

        osvi.dwMajorVersion = wMajorVersion;
        osvi.dwMinorVersion = wMinorVersion;
        osvi.wServicePackMajor = wServicePackMajor;

        return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
    }

    VERSIONHELPERAPI
    IsWindowsVistaOrGreater()
    {
        return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 0);
    }

#ifdef __cplusplus
}
#endif
