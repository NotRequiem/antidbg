#include "clshandle.h"

bool CheckCloseHandle()
{
    __try
    {
        CloseHandle((HANDLE)(uintptr_t)0xDEADBEEF);
        return false;
    }
    __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return true;
    }
}
