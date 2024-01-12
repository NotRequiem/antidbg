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
        return false;
    }
}
