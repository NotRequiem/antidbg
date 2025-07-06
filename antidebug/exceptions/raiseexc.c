#include "raiseexc.h"

bool RaiseDbgControl()
{
    __try
    {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL); // or DBG_RIPEVENT, no longer existent in winnt.h
        return true;
    }
    __except (GetExceptionCode() == DBG_CONTROL_C
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        __try
        {
            RaiseException(DBG_RIPEXCEPTION, 0, 0, 0);
        }
        __except (1)
        {
            return FALSE;
        }
        return TRUE;
    }
}