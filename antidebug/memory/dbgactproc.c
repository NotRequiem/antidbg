#include "dbgactproc.h"

// note: syscalling this code would not be helpful, as you will need to use at some point an API call that can't be syscalled (and thus, can be trivially hooked). 

bool SelfDebugging(const char* cpid)
{
    BOOL found = FALSE;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    TCHAR szPath[MAX_PATH];
    DWORD exitCode = 0;

    CreateMutexW(NULL, FALSE, L"__adbg");
    if (GetLastError() != ERROR_SUCCESS)
    {
        if (DebugActiveProcess((DWORD)atoi(cpid)))
        {
            return false;
        }
        else
        {
            exit(7892);
        }
    }

    DWORD pid = GetCurrentProcessId();
    GetModuleFileName(NULL, szPath, MAX_PATH);

    char cmdline[MAX_PATH + 1 + sizeof(int)];
    snprintf(cmdline, sizeof(cmdline), "%s %d", (LPCTSTR)szPath, pid);

    CreateProcessA(
        NULL,		
        cmdline,	
        NULL,		
        NULL,		
        FALSE,		
        0,			
        NULL,		
        NULL,		
        &si,		
        &pi);		

    WaitForSingleObject(pi.hProcess, INFINITE);

    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (exitCode == 7892)
    {
        found = TRUE;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return found;
}