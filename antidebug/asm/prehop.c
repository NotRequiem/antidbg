#include "prehop.h"

bool PrefixHop()
{
    BOOL found = TRUE;

    __try
    {
        unsigned char code[] = {
            0xF3, // REP prefix
            0x64, // FS prefix
            0xCC  // software bp
        };
        void (*func)() = (void (*)())code;
        func(); 
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE; // exception handler triggers if INT 3 is skipped
    }

    return found;
}
