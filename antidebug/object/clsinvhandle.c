#include "clsinvhandle.h"

bool CloseInvalidHandle()
{
    __try {
        CloseHandle((HANDLE)0x99999999ULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }

    if (NtClose_InvalideHandle())
        return TRUE;
    else
        return FALSE;
}
