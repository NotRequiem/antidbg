#include "loadlib.h"

bool CheckLoadLibrary()
{
    CHAR szBuffer[] = { "C:\\Windows\\System32\\calc.exe" };
    LoadLibraryA(szBuffer);
    return INVALID_HANDLE_VALUE == CreateFileA(szBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}