#include "prntproc.h"
#include "../core/syscall.h"

typedef struct _DBG_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} DBG_PROCESS_BASIC_INFORMATION, * PDBG_PROCESS_BASIC_INFORMATION;

static DWORD GetParentProcessIdFromHandle(HANDLE hProcess)
{
    DBG_PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength;
    const NTSTATUS status = DbgNtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status >= 0) { 
        return (DWORD)pbi.InheritedFromUniqueProcessId;
    }

    return 0;
}

bool ParentProcesses(const HANDLE hProcess)
{
    const WCHAR* whitelist[] = {
        L"explorer.exe",
        L"cmd.exe",
        L"powershell.exe",
        L"svchost.exe",
        L"services.exe",
        L"wininit.exe",
        L"lsass.exe",
        L"devenv.exe",       
     // L"msvsmon.exe",       // Visual Studio Remote Debugger
        L"wsl.exe",           
        L"WindowsTerminal.exe",
        L"taskhostw.exe"
    };

    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W pe32 = { 0 };
    bool isSuspicious = TRUE; 

    const DWORD ppid = GetParentProcessIdFromHandle(hProcess);
    if (ppid == 0) {
        return FALSE;
    }

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE; 
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == ppid) {
                for (int i = 0; i < (sizeof(whitelist) / sizeof(whitelist[0])); i++) {
                    if (_wcsicmp(pe32.szExeFile, whitelist[i]) == 0) {
                        isSuspicious = FALSE;
                        break;
                    }
                }
                break; 
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    else {
        isSuspicious = FALSE;
    }

    DbgNtClose(hSnapshot);

    // If the parent process was not found in the snapshot isSuspicious will remain TRUE

    return isSuspicious;
}