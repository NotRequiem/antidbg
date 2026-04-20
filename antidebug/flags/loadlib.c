#include "loadlib.h"

static inline bool _check_end_update_resource() 
{
    bool detected = FALSE;
    CHAR temp_file[MAX_PATH];
    char* temp_path = NULL;
    size_t len = 0;

    if (_dupenv_s(&temp_path, &len, "TEMP") != 0 || temp_path == NULL) {
        return FALSE;
    }

    if (!GetTempFileNameA(temp_path, "dbg", 0, temp_file)) {
        free(temp_path);
        return FALSE;
    }

    free(temp_path);

    const HANDLE hFile = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    CloseHandle(hFile);

    const HMODULE library_handle = LoadLibraryA(temp_file);
    const HANDLE update_handle = BeginUpdateResourceA(temp_file, FALSE);

    if (update_handle != NULL) {
        if (!EndUpdateResourceA(update_handle, TRUE)) {
            detected = TRUE;
        }
    }

    if (library_handle) {
        FreeLibrary(library_handle);
    }

    DeleteFileA(temp_file);

    return detected;
}

static inline bool _check_read_file_breakpoint() {
    bool detected = TRUE;
    char self_path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, self_path, MAX_PATH)) {
        return false;
    }

    const HANDLE self_handle = CreateFileA(self_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (self_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    unsigned char breakpoint_check[] = { 0xCC }; // int 3

    const LPVOID code = VirtualAlloc(NULL, sizeof(breakpoint_check), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!code) {
        CloseHandle(self_handle);
        return false;
    }

    if (memcpy_s(code, sizeof(breakpoint_check), breakpoint_check, sizeof(breakpoint_check)) != 0) {
        VirtualFree(code, 0, MEM_RELEASE);
        CloseHandle(self_handle);
        return false;
    }

    DWORD read = 0;
    if (!ReadFile(self_handle, code, 1, &read, NULL) || read != 1) {
        VirtualFree(code, 0, MEM_RELEASE);
        CloseHandle(self_handle);
        return false;
    }

    CloseHandle(self_handle);

    __try {
        ((void(*)())code)();
        detected = false;
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        detected = true;
    }

    VirtualFree(code, 0, MEM_RELEASE);
    return detected;
}

bool __adbg_load_library() 
{
    if (_check_read_file_breakpoint() || _check_end_update_resource())
        return true;

    bool debugged = false;
    CHAR temp_path[MAX_PATH];
    CHAR temp_file[MAX_PATH];

    if (!GetTempPathA(MAX_PATH, temp_path)) return false;
    if (!GetTempFileNameA(temp_path, "dbg", 0, temp_file)) return false;

    const HANDLE file_handle = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) return false;
    CloseHandle(file_handle);

    // we expect this to fail, but that's okay
    const HMODULE library_handle = LoadLibraryA(temp_file);

    // now, try to open the file with exclusive access
    // a debugger holding a handle will cause this to fail with ERROR_SHARING_VIOLATION
    const HANDLE file_exclusive = CreateFileA(temp_file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_exclusive == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_SHARING_VIOLATION) {
            debugged = true;
        }
    }
    else {
        CloseHandle(file_exclusive);
    }

    if (library_handle) FreeLibrary(library_handle);
    DeleteFileA(temp_file);

    return debugged;
}
