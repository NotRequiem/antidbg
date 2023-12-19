#include "popf.h"

bool POPFTrapFlag()
{
    __try
    {
        RaiseException(EXCEPTION_TRAP_FLAG, 0, 0, NULL);

        // Code that will be executed if no exception is raised
        return true;
    }
    __except (GetExceptionCode() == EXCEPTION_TRAP_FLAG
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_EXECUTION)
    {
        // Code that will be executed if the exception is caught
        return false;
    }
}