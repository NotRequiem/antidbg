#include "ntglobalflag.h"

bool NtGlobalFlag()
{
    PDWORD pNtGlobalFlag = NULL, pNtGlobalFlagWoW64 = NULL;

    pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);

    const bool normalDetected = pNtGlobalFlag && *pNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED;
    const bool wow64Detected = pNtGlobalFlagWoW64 && *pNtGlobalFlagWoW64 & NT_GLOBAL_FLAG_DEBUGGED;

    return normalDetected || wow64Detected;
}
