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
        return false;
    }
}