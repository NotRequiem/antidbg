#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include "pgexcbp.h"

void** executablePages = NULL;
size_t executablePagesCount = 0;

static void PageExceptionInitialEnum()
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    size_t pageSize = sysInfo.dwPageSize;

    HMODULE hMainModule;
    MODULEINFO moduleInfo;

    MEMORY_BASIC_INFORMATION memInfo = { 0 };

    if (!(executablePages = malloc(1 * sizeof(void*)))) {
        return;
    }

    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)PageExceptionBreakpoint, &hMainModule))
    {
        if (GetModuleInformation(GetCurrentProcess(), hMainModule, &moduleInfo, sizeof(MODULEINFO)))
        {
            unsigned char* module = (unsigned char*)moduleInfo.lpBaseOfDll;
            for (size_t ofs = 0; ofs < moduleInfo.SizeOfImage; ofs += pageSize)
            {
                if (VirtualQuery(module + ofs, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
                {
                    if ((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
                        (memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
                        (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
                        (memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
                    {
                        void** temp = realloc(executablePages, (executablePagesCount + 1) * sizeof(void*));
                        if (!temp) {
                            free(executablePages);
                            executablePages = NULL;
                            return;
                        }
                        executablePages = temp;
                        executablePages[executablePagesCount++] = module + ofs;
                    }
                }
            }
        }
    }
}

static void freeExecutablePages() {
    free(executablePages);
    executablePages = NULL;
    executablePagesCount = 0;
}

bool PageExceptionBreakpoint()
{
    if (executablePages == NULL) {
        PageExceptionInitialEnum();
        if (executablePages == NULL) {
            return FALSE;
        }
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    size_t pageSize = sysInfo.dwPageSize;

    HMODULE hMainModule;
    MODULEINFO moduleInfo;

    MEMORY_BASIC_INFORMATION memInfo = { 0 };

    wchar_t buffer[512] = { 0 };

    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)PageExceptionBreakpoint, &hMainModule))
    {
        if (GetModuleInformation(GetCurrentProcess(), hMainModule, &moduleInfo, sizeof(MODULEINFO)))
        {
            unsigned char* module = (unsigned char*)moduleInfo.lpBaseOfDll;
            for (size_t ofs = 0; ofs < moduleInfo.SizeOfImage; ofs += pageSize)
            {
                SecureZeroMemory(buffer, 512);
                swprintf(buffer, 512, L"Scanning %p... ", (void*)(module + ofs));
                OutputDebugStringW(buffer);
                if (VirtualQuery(module + ofs, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
                {
                    if (memInfo.AllocationProtect == 0)
                        OutputDebugStringW(L"^ AllocationProtect is zero. Potential shenanigans.");
                    if (memInfo.Protect == 0)
                        OutputDebugStringW(L"^ Protect is zero. Potential shenanigans.");

                    if ((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
                        (memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
                        (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
                        (memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
                    {
                        OutputDebugStringW(L"^ is executable.");

                        if ((memInfo.Protect & PAGE_GUARD) == PAGE_GUARD ||
                            (memInfo.AllocationProtect & PAGE_GUARD) == PAGE_GUARD)
                        {
                            OutputDebugStringW(L"^ is guard page !!!!!!");
                            return TRUE;
                        }
                    }

                    if ((memInfo.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
                    {
                        OutputDebugStringW(L"^ is NOACCESS !!!!!!!");
                        return TRUE;
                    }
                }
                else OutputDebugStringW(L"^ FAILED!");
            }
        }

        OutputDebugStringW(L"Moving on to delta check...");

        for (size_t i = 0; i < executablePagesCount; ++i)
        {
            SecureZeroMemory(buffer, 512);
            swprintf(buffer, 512, L"Scanning delta for %p... ", (void*)(executablePages[i]));
            OutputDebugStringW(buffer);

            if (VirtualQuery(executablePages[i], &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
            {
                if (memInfo.AllocationProtect == 0)
                    OutputDebugStringW(L"^ AllocationProtect is zero. Potential shenanigans.");
                if (memInfo.Protect == 0)
                    OutputDebugStringW(L"^ Protect is zero. Potential shenanigans.");

                if (!((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
                    (memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
                    (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
                    (memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE))
                {
                    OutputDebugStringW(L"^ was executable, now isn't !!!!!!");
                    return TRUE;
                }
            }
        }
    }

    freeExecutablePages();

    return FALSE;
}
