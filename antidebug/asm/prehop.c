#include "prehop.h"

bool __adbg_prefix_hop()
{
    bool found = true;

    __try
    {
        const unsigned char code[] = {
            0xF3, // REP prefix
            0x64, // FS prefix
            0xF1  // software bp
        };
        void (*func)() = (void (*)())code;
        func(); 
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = false; // exception handler triggers if INT 1 is skipped
    }

    return found;
}
