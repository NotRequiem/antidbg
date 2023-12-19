#include "crtfile.h"

bool CheckCreateFile()
{
    CHAR szFileName[MAX_PATH];
    if (0 == GetModuleFileNameA(NULL, szFileName, sizeof(szFileName)))
        return false;

    HANDLE hFile = CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        // The file couldn't be opened exclusively, indicating the possible presence of a debugger.
        CloseHandle(hFile);
        return true;
    }

    // Close the handle and return false, indicating that no debugger is detected.
    CloseHandle(hFile);
    return false;
}