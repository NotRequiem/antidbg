#include "dbgprintex.h"

/* In development */
#define DBG_PRINTEXCEPTION_C 0x40010006

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

int main()
{
    if (DBG_PRINTEXCEPTION())
    {
        printf("Debugger detected!\n");
    }
    else
    {
        printf("No debugger detected.\n");
    }

    return 0;
}
