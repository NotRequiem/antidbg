#include "prehop.h"

bool PrefixHop()
{
    BOOL found = TRUE;

    __try
    {
        // x64 Version: Emit instructions as a code block and execute them
        unsigned char code[] = {
            0xF3, // REP prefix
            0x64, // FS prefix
            0xCC  // INT 3 (software breakpoint)
        };
        void (*func)() = (void (*)())code;
        func(); // Execute the code block
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        found = FALSE; // Exception handler triggers if INT 3 is skipped
    }

    return found;
}
