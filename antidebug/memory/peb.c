#include "peb.h"
#include "../core/nttypes.h"

bool CheckPEB() 
{
    PEB* peb = (PEB*)__readgsqword(0x60);
    if (!peb) {
        return false;
    }
    return (*(BYTE*)((uintptr_t)peb + 2)) != 0;
}