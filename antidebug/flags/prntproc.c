#include "prntproc.h"
#include "../core/syscall.h"
#include <stdbool.h>

typedef struct _DBG_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} DBG_PROCESS_BASIC_INFORMATION, * PDBG_PROCESS_BASIC_INFORMATION;

static inline bool _compare_str(const UNICODE_STRING* process_name, const WCHAR* target_name)
{
    if (!process_name || !process_name->Buffer || !target_name)
        return false;

    SIZE_T target_len = 0;
    while (target_name[target_len] != L'\0') {
        target_len++;
    }

    // length is in bytes, so we divide by sizeof(WCHAR) to get character count
    if ((process_name->Length / sizeof(WCHAR)) != target_len)
        return false;

    for (SIZE_T i = 0; i < target_len; i++) {
        WCHAR c1 = process_name->Buffer[i];
        WCHAR c2 = target_name[i];

        if (c1 >= L'A' && c1 <= L'Z') c1 += (L'a' - L'A');
        if (c2 >= L'A' && c2 <= L'Z') c2 += (L'a' - L'A');

        if (c1 != c2)
            return false;
    }

    return true;
}

static inline DWORD _read_parent_processid(HANDLE process_handle)
{
    DBG_PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG return_length = 0;

    // 0 = ProcessBasicInformation
    const NTSTATUS status = DbgNtQueryInformationProcess(
        process_handle,
        0,
        &pbi,
        sizeof(pbi),
        &return_length
    );

    if (status >= 0) {
        return (DWORD)pbi.InheritedFromUniqueProcessId;
    }

    return 0;
}

bool __adbg_parent_processes(const HANDLE process_handle)
{
    const WCHAR* whitelist[] = {
        L"explorer.exe",
        L"cmd.exe",
        L"powershell.exe",
        L"pwsh.exe",
        L"svchost.exe",
        L"services.exe",
        L"wininit.exe",
        L"winlogon.exe",
        L"userinit.exe",
        L"lsass.exe",
        L"devenv.exe",
        L"wsl.exe",
        L"WindowsTerminal.exe",
        L"taskhostw.exe",
        L"taskmgr.exe",
        L"msiexec.exe",
        L"mmc.exe",
        L"rundll32.exe",
        L"regsvr32.exe",
        L"wscript.exe",
        L"cscript.exe",
        L"mshta.exe",
        L"control.exe",
        L"RuntimeBroker.exe",
        L"StartMenuExperienceHost.exe"
    };

    bool is_suspicious = true;

    const DWORD ppid = _read_parent_processid(process_handle);
    if (ppid == 0) {
        return false;
    }

    ULONG return_length = 0;
    HANDLE current_process = (HANDLE)-1;

    // 5 = SystemProcessInformation, first call determines buffer size required
    DbgNtQuerySystemInformation(5, NULL, 0, &return_length);
    if (return_length == 0) {
        return false;
    }

    // Add padding in case new processes spawn before the second call
    return_length += (1024 * 10);

    PVOID snapshot_buffer = NULL;
    SIZE_T alloc_size = return_length;

    if (DbgNtAllocateVirtualMemory(current_process, &snapshot_buffer, 0, &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) < 0) {
        return false;
    }

    if (DbgNtQuerySystemInformation(5, snapshot_buffer, (ULONG)alloc_size, &return_length) >= 0) {
        PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)snapshot_buffer;

        while (true) {
            const DWORD current_pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;

            if (current_pid == ppid) {
                for (size_t i = 0; i < (sizeof(whitelist) / sizeof(whitelist[0])); i++) {
                    if (_compare_str(&spi->ImageName, whitelist[i])) {
                        is_suspicious = false;
                        break;
                    }
                }
                break;
            }

            if (!spi->NextEntryOffset) {
                break;
            }
            spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
        }
    }
    else {
        is_suspicious = false;
    }

    if (snapshot_buffer) {
        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(current_process, &snapshot_buffer, &free_size, MEM_RELEASE);
    }

    // if the parent process was not found in the snapshot isSuspicious will remain TRUE

    return is_suspicious;
}