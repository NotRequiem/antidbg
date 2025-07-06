#include "int2d.h"

bool int2D()
{
    __try
    {
        RaiseException(0x80000003, 0, 0, NULL);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        __try
        {
            RaiseException(0x2D, 0, 0, NULL);
        }
        __except (1)
        {
            return FALSE;
        }
        return TRUE;
    }
}
