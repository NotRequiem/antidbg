#include "pgexcbp.h"
#include "..\core\syscall.h"

void** executablePages = NULL;
size_t executablePagesCount = 0;

static inline void __fastcall PageExceptionInitialEnum(const HANDLE hProcess)
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
        if (GetModuleInformation(hProcess, hMainModule, &moduleInfo, sizeof(MODULEINFO)))
        {
            unsigned char* module = (unsigned char*)moduleInfo.lpBaseOfDll;
            for (size_t ofs = 0; ofs < moduleInfo.SizeOfImage; ofs += pageSize)
            {
                SIZE_T returnLength = 0;
                NTSTATUS status = DbgNtQueryVirtualMemory(hProcess, module + ofs, MemoryBasicInformation, &memInfo, sizeof(memInfo), &returnLength);
                if (((NTSTATUS)(status) >= 0) && returnLength >= sizeof(MEMORY_BASIC_INFORMATION))
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

static inline void freeExecutablePages() {
    free(executablePages);
    executablePages = NULL;
    executablePagesCount = 0;
}

bool PageExceptionBreakpoint(const HANDLE hProcess)
{
    if (executablePages == NULL) {
        PageExceptionInitialEnum(hProcess);
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
        if (GetModuleInformation(hProcess, hMainModule, &moduleInfo, sizeof(MODULEINFO)))
        {
            unsigned char* module = (unsigned char*)moduleInfo.lpBaseOfDll;
            for (size_t ofs = 0; ofs < moduleInfo.SizeOfImage; ofs += pageSize)
            {
                SecureZeroMemory(buffer, 512);
                SIZE_T returnLength = 0;
                NTSTATUS status = DbgNtQueryVirtualMemory(hProcess, module + ofs, MemoryBasicInformation, &memInfo, sizeof(memInfo), &returnLength);
                if (((NTSTATUS)(status) >= 0) && returnLength >= sizeof(MEMORY_BASIC_INFORMATION))
                {
                    if (memInfo.AllocationProtect == 0)
                        OutputDebugStringA("^ AllocationProtect is zero. Potential shenanigans.");
                    if (memInfo.Protect == 0)
                        OutputDebugStringA("^ Protect is zero. Potential shenanigans.");

                    if ((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
                        (memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
                        (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
                        (memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
                    {

                        if ((memInfo.Protect & PAGE_GUARD) == PAGE_GUARD ||
                            (memInfo.AllocationProtect & PAGE_GUARD) == PAGE_GUARD)
                        {
                            return TRUE;
                        }
                    }

                    if ((memInfo.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
                    {
                        return TRUE;
                    }
                }
            }
        }

        for (size_t i = 0; i < executablePagesCount; ++i)
        {
            SecureZeroMemory(buffer, 512);

            SIZE_T returnLength = 0;
            NTSTATUS status = DbgNtQueryVirtualMemory(hProcess, executablePages[i], MemoryBasicInformation, &memInfo, sizeof(memInfo), &returnLength);
            if (((NTSTATUS)(status) >= 0) && returnLength >= sizeof(MEMORY_BASIC_INFORMATION))
            {
                if (memInfo.AllocationProtect == 0)
                    OutputDebugStringA("^ AllocationProtect is zero. Potential shenanigans.");
                if (memInfo.Protect == 0)
                    OutputDebugStringA("^ Protect is zero. Potential shenanigans.");

                if (!((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
                    (memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
                    (memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
                    (memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE))
                {
                    return TRUE;
                }
            }
        }
    }

    freeExecutablePages();

    return FALSE;
}
