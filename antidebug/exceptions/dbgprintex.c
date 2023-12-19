
#include "dbgprintex.h"

bool DBG_PRINTEXCEPTION()
{
    __try
    {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, NULL);
    }
    __except (GetExceptionCode() == DBG_PRINTEXCEPTION_C)
    {
        return true;
    }

    return false;
}