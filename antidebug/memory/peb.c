#include "peb.h"

#if defined (BIT64)
#define READ_PEB_OFFSET 0x60

#elif defined(BIT32)
#define READ_PEB_OFFSET 0x30

#endif

bool CheckPEB() {
    PEB* peb = (PEB*)__readgsqword(READ_PEB_OFFSET);
    return (*(BYTE*)((uintptr_t)peb + 2)) != 0;
}
