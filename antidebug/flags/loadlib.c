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

    DWORD old_error_mode = 0;
    SetThreadErrorMode(SEM_FAILCRITICALERRORS, &old_error_mode);

    const HMODULE library_handle = LoadLibraryA(temp_file);

    SetThreadErrorMode(old_error_mode, NULL);

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
    bool detected = false;
    char self_path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, self_path, MAX_PATH)) return false;

    HANDLE self_handle = CreateFileA(self_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (self_handle == INVALID_HANDLE_VALUE) return false;

    unsigned char first_byte = 0;
    DWORD read = 0;
    if (ReadFile(self_handle, &first_byte, 1, &read, NULL) && read == 1) {
        if (first_byte == 0xCC) detected = true;
    }

    CloseHandle(self_handle);
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

    // to suppress the "Bad Image" hard error
    DWORD old_error_mode = 0;
    SetThreadErrorMode(SEM_FAILCRITICALERRORS, &old_error_mode);

    // we expect this to fail, but it's okay
    const HMODULE library_handle = LoadLibraryA(temp_file);

    // Restore previous error mode
    SetThreadErrorMode(old_error_mode, NULL);

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