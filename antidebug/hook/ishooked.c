#include "ishooked.h"

bool IsHooked()
{
    BOOL bFirstResult = FALSE, bSecondResult = FALSE;

    __try
    {
        bFirstResult = BlockInput(TRUE);

        Sleep(100);

        bSecondResult = BlockInput(TRUE);
    }
    __finally
    {
        BlockInput(FALSE);
    }

    return bFirstResult && bSecondResult;
}