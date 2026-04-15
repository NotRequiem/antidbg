#include "loadlib.h"

static bool CheckEndUpdateResource() 
{
    bool bDetected = FALSE;
    CHAR szTempFile[MAX_PATH];
    char* tempPath = NULL;
    size_t len = 0;

    if (_dupenv_s(&tempPath, &len, "TEMP") != 0 || tempPath == NULL) {
        return FALSE;
    }

    if (!GetTempFileNameA(tempPath, "dbg", 0, szTempFile)) {
        free(tempPath);
        return FALSE;
    }

    free(tempPath);

    const HANDLE hFile = CreateFileA(szTempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    CloseHandle(hFile);

    const HMODULE hLib = LoadLibraryA(szTempFile);
    const HANDLE hUpdate = BeginUpdateResourceA(szTempFile, FALSE);

    if (hUpdate != NULL) {
        if (!EndUpdateResourceA(hUpdate, TRUE)) {
            bDetected = TRUE;
        }
    }

    if (hLib) {
        FreeLibrary(hLib);
    }

    DeleteFileA(szTempFile);

    return bDetected;
}

static bool CheckReadFileBreakpoint() {
    bool bDetected = TRUE;
    char szSelfPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, szSelfPath, MAX_PATH)) {
        return false;
    }

    const HANDLE hSelf = CreateFileA(szSelfPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) {
        return false;
    }

    unsigned char breakpoint_check[] = { 0xCC }; // int 3

    const LPVOID pCode = VirtualAlloc(NULL, sizeof(breakpoint_check), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pCode) {
        CloseHandle(hSelf);
        return false;
    }

    if (memcpy_s(pCode, sizeof(breakpoint_check), breakpoint_check, sizeof(breakpoint_check)) != 0) {
        VirtualFree(pCode, 0, MEM_RELEASE);
        CloseHandle(hSelf);
        return false;
    }

    DWORD dwRead = 0;
    if (!ReadFile(hSelf, pCode, 1, &dwRead, NULL) || dwRead != 1) {
        VirtualFree(pCode, 0, MEM_RELEASE);
        CloseHandle(hSelf);
        return false;
    }

    CloseHandle(hSelf);

    __try {
        ((void(*)())pCode)();
        bDetected = false;
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        bDetected = true;
    }

    VirtualFree(pCode, 0, MEM_RELEASE);
    return bDetected;
}

bool CheckLoadLibrary() 
{
    if (CheckReadFileBreakpoint() || CheckEndUpdateResource())
        return true;

    bool bDebuggerPresent = false;
    CHAR szTempPath[MAX_PATH];
    CHAR szTempFile[MAX_PATH];

    if (!GetTempPathA(MAX_PATH, szTempPath)) return false;
    if (!GetTempFileNameA(szTempPath, "dbg", 0, szTempFile)) return false;

    const HANDLE hFile = CreateFileA(szTempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    CloseHandle(hFile);

    // we expect this to fail, but that's okay
    const HMODULE hLib = LoadLibraryA(szTempFile);

    // now, try to open the file with exclusive access
    // a debugger holding a handle will cause this to fail with ERROR_SHARING_VIOLATION
    const HANDLE hFileExclusive = CreateFileA(szTempFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFileExclusive == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_SHARING_VIOLATION) {
            bDebuggerPresent = true;
        }
    }
    else {
        CloseHandle(hFileExclusive);
    }

    if (hLib) FreeLibrary(hLib);
    DeleteFileA(szTempFile);

    return bDebuggerPresent;
}
