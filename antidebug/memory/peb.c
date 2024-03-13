#include "peb.h"

bool CheckPEB() {
    PEB* peb = (PEB*)__readgsqword(0x60);
    return (*(BYTE*)((uintptr_t)peb + 2)) != 0;
}
