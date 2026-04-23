#include "ntglobalflag.h"

bool __adbg_nt_global_flag()
{
    PDWORD nt_global_flag = NULL, nt_global_flag_wow64 = NULL;

    nt_global_flag = (PDWORD)(__readgsqword(0x60) + 0xBC);

    const bool normaldetected = nt_global_flag && *nt_global_flag & NT_GLOBAL_FLAG_DEBUGGED;
    const bool wow64_detected = nt_global_flag_wow64 && *nt_global_flag_wow64 & NT_GLOBAL_FLAG_DEBUGGED;

    return normaldetected || wow64_detected;
}
