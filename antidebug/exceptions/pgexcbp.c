#include "pgexcbp.h"
#include "..\core\syscall.h"

void** executablePages = NULL;
size_t executablePagesCount = 0;

static inline void __fastcall PageExceptionInitialEnum(const HANDLE hProcess)
{
    SYSTEM_INFO sysInfo; GetSystemInfo(&sysInfo);
    size_t       pageSize = sysInfo.dwPageSize;
    HMODULE      hMainModule;
    MODULEINFO   moduleInfo;
    MEMORY_BASIC_INFORMATION memInfo;

    if (!(executablePages = malloc(sizeof(void*))))
        return;

    if (GetModuleHandleEx(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCTSTR)PageExceptionBreakpoint,
        &hMainModule) &&
        GetModuleInformation(
            hProcess, hMainModule,
            &moduleInfo, sizeof(moduleInfo)))
    {
        unsigned char* module = (unsigned char*)moduleInfo.lpBaseOfDll;
        for (size_t ofs = 0; ofs < moduleInfo.SizeOfImage; ofs += pageSize)
        {
            SIZE_T returnLength = 0;
            NTSTATUS  status = DbgNtQueryVirtualMemory(
                hProcess,
                module + ofs,
                MemoryBasicInformation,
                &memInfo,
                sizeof(memInfo),
                &returnLength);

            if (status >= 0 && returnLength >= sizeof(memInfo))
            {
                const DWORD execMask =
                    PAGE_EXECUTE |
                    PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE |
                    PAGE_EXECUTE_WRITECOPY;

                if (memInfo.Protect & execMask)
                {
                    void** tmp = realloc(
                        executablePages,
                        (executablePagesCount + 1) * sizeof(void*));
                    if (!tmp) { free(executablePages); executablePages = NULL; return; }
                    executablePages = tmp;
                    executablePages[executablePagesCount++] = module + ofs;
                }
            }
        }
    }
}

static inline void freeExecutablePages(void)
{
    free(executablePages);
    executablePages = NULL;
    executablePagesCount = 0;
}

static BOOL TestDeltaExecLoss(
    HANDLE hProcess,
    PVOID  addr,
    MEMORY_BASIC_INFORMATION* pInfo)
{
    SIZE_T   retLen = 0;
    NTSTATUS st = DbgNtQueryVirtualMemory(
        hProcess,
        addr,
        MemoryBasicInformation,
        pInfo,
        sizeof(*pInfo),
        &retLen);

    if (st < 0 || retLen < sizeof(*pInfo))
        return FALSE;

    const DWORD execMask =
        PAGE_EXECUTE |
        PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY;

    // if it used to be exec but now isn't then debugger trap
    return ((pInfo->Protect & execMask) == 0);
}

bool PageExceptionBreakpoint(const HANDLE hProcess)
{
    bool found = FALSE;
    MEMORY_BASIC_INFORMATION memInfo = { 0 };

    if (executablePages == NULL)
    {
        PageExceptionInitialEnum(hProcess);
        if (executablePages == NULL)
            return FALSE;
    }

    // guard / NOACCESS on any module page
    HMODULE    hMod = NULL;
    MODULEINFO modInfo = { 0 };
    if (!GetModuleHandleEx(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCTSTR)PageExceptionBreakpoint,
        &hMod) ||
        !GetModuleInformation(
            hProcess,
            hMod,
            &modInfo,
            sizeof(modInfo)))
    {
        freeExecutablePages();
        return FALSE;
    }

    SYSTEM_INFO si; GetSystemInfo(&si);
    size_t       pageSize = si.dwPageSize;
    BYTE* base = (BYTE*)modInfo.lpBaseOfDll;

    const DWORD execMask =
        PAGE_EXECUTE |
        PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY;

    for (size_t ofs = 0; ofs < modInfo.SizeOfImage; ofs += pageSize)
    {
        SIZE_T   retLen = 0;
        NTSTATUS st = DbgNtQueryVirtualMemory(
            hProcess,
            base + ofs,
            MemoryBasicInformation,
            &memInfo,
            sizeof(memInfo),
            &retLen);

        if (st >= 0 && retLen >= sizeof(memInfo))
        {
            // only if this page is executable do we check guard
            if (memInfo.Protect & execMask)
            {
                if ((memInfo.Protect & PAGE_GUARD) ||
                    (memInfo.AllocationProtect & PAGE_GUARD))
                {
                    found = TRUE;
                    break;
                }
            }
            // NOACCESS check applies to any page
            if (memInfo.Protect & PAGE_NOACCESS)
            {
                found = TRUE;
                break;
            }
        }
    }

    // check our snapshot for lost exec perms
    if (!found)
    {
        for (size_t i = 0; i < executablePagesCount; ++i)
        {
            if (TestDeltaExecLoss(
                hProcess,
                executablePages[i],
                &memInfo))
            {
                found = TRUE;
                break;
            }
        }
    }

    freeExecutablePages();
    return found;
}
