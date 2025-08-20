#include "loadlib.h"

static bool CheckEndUpdateResource() {
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

    HANDLE hFile = CreateFileA(szTempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    CloseHandle(hFile);

    HMODULE hLib = LoadLibraryA(szTempFile);
    HANDLE hUpdate = BeginUpdateResourceA(szTempFile, FALSE);

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
    if (!GetModuleFileNameA(NULL, szSelfPath, MAX_PATH)) return FALSE;
    HANDLE hSelf = CreateFileA(szSelfPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) return FALSE;

    unsigned char breakpoint_check[] = { 0xCC }; // INT 3
    LPVOID pCode = VirtualAlloc(NULL, sizeof(breakpoint_check), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pCode) { CloseHandle(hSelf); return FALSE; }
    memcpy(pCode, breakpoint_check, sizeof(breakpoint_check));

    DWORD dwRead;
    if (!ReadFile(hSelf, pCode, 1, &dwRead, NULL)) {
        CloseHandle(hSelf);
        return FALSE;
    }
    CloseHandle(hSelf);

    __try {
        ((void(*)())pCode)();
        bDetected = FALSE; 
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        bDetected = TRUE; 
    }

    VirtualFree(pCode, 0, MEM_RELEASE);
    return bDetected;
}

bool CheckLoadLibrary() 
{
    if (CheckReadFileBreakpoint() || CheckEndUpdateResource())
        return TRUE;

    bool bDebuggerPresent = FALSE;
    CHAR szTempPath[MAX_PATH];
    CHAR szTempFile[MAX_PATH];

    if (!GetTempPathA(MAX_PATH, szTempPath)) return FALSE;
    if (!GetTempFileNameA(szTempPath, "dbg", 0, szTempFile)) return FALSE;

    HANDLE hFile = CreateFileA(szTempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    CloseHandle(hFile);

    // we expect this to fail, but that's okay
    HMODULE hLib = LoadLibraryA(szTempFile);

    // now, try to open the file with exclusive access
    // a debugger holding a handle will cause this to fail with ERROR_SHARING_VIOLATION
    HANDLE hFileExclusive = CreateFileA(szTempFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFileExclusive == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_SHARING_VIOLATION) {
            bDebuggerPresent = TRUE;
        }
    }
    else {
        CloseHandle(hFileExclusive);
    }

    if (hLib) FreeLibrary(hLib);
    DeleteFileA(szTempFile);

    return bDebuggerPresent;
}