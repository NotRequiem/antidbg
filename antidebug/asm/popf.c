#include "popf.h"

bool POPFTrapFlag()
{
    __try
    {
        RaiseException(EXCEPTION_TRAP_FLAG, 0, 0, NULL);

        return true;
    }
    __except (GetExceptionCode() == EXCEPTION_TRAP_FLAG
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_EXECUTION)
    {
        return false;
    }
}