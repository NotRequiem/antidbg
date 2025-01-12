#include "ntglobalflag.h"

bool NtGlobalFlag()
{
    PDWORD pNtGlobalFlag = NULL, pNtGlobalFlagWoW64 = NULL;

    pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);

    BOOL normalDetected = pNtGlobalFlag && *pNtGlobalFlag & 0x00000070;
    BOOL wow64Detected = pNtGlobalFlagWoW64 && *pNtGlobalFlagWoW64 & 0x00000070;

    return normalDetected || wow64Detected;
}
