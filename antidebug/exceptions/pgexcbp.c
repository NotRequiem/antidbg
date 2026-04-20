#include "pgexcbp.h"
#include "..\core\syscall.h"

void** executable_pages = NULL;
size_t executablePagesCount = 0;

static inline void _page_exception_initial_enum(const HANDLE process_handle)
{
    size_t                   page_size = PAGE_SIZE;
    MEMORY_BASIC_INFORMATION mem_info = { 0 };

    if (!(executable_pages = malloc(sizeof(void*))))
        return;

    if (NT_SUCCESS(DbgNtQueryVirtualMemory(
        process_handle,
        (PVOID)__adbg_page_exception_breakpoint,
        MemoryBasicInformation,
        &mem_info,
        sizeof(mem_info),
        NULL)))
    {
        PVOID main_module = mem_info.AllocationBase;
        if (!main_module) return;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)main_module;

        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)main_module + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
            {
                SIZE_T size_of_image = nt->OptionalHeader.SizeOfImage;
                unsigned char* module = (unsigned char*)main_module;

                for (size_t ofs = 0; ofs < size_of_image; ofs += page_size)
                {
                    SIZE_T return_length = 0;
                    const NTSTATUS status = DbgNtQueryVirtualMemory(
                        process_handle,
                        module + ofs,
                        MemoryBasicInformation,
                        &mem_info,
                        sizeof(mem_info),
                        &return_length);

                    if (status >= 0 && return_length >= sizeof(mem_info))
                    {
                        const DWORD exec_mask =
                            PAGE_EXECUTE |
                            PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE |
                            PAGE_EXECUTE_WRITECOPY;

                        if (mem_info.Protect & exec_mask)
                        {
                            void** tmp = realloc(
                                executable_pages,
                                (executablePagesCount + 1) * sizeof(void*));
                            if (!tmp) { free(executable_pages); executable_pages = NULL; return; }
                            executable_pages = tmp;
                            executable_pages[executablePagesCount++] = module + ofs;
                        }
                    }
                }
            }
        }
    }
}

static inline void _free_pages(void)
{
    free(executable_pages);
    executable_pages = NULL;
    executablePagesCount = 0;
}

static BOOL _test_delta_exec_loss(
    HANDLE process_handle,
    PVOID  addr,
    MEMORY_BASIC_INFORMATION* pInfo)
{
    SIZE_T return_length = 0;
    const NTSTATUS status = DbgNtQueryVirtualMemory(
        process_handle,
        addr,
        MemoryBasicInformation,
        pInfo,
        sizeof(*pInfo),
        &return_length);

    if (status < 0 || return_length < sizeof(*pInfo))
        return FALSE;

    const DWORD exec_mask =
        PAGE_EXECUTE |
        PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY;

    // if it used to be exec but now isn't then debugger trap
    return ((pInfo->Protect & exec_mask) == 0);
}

bool __adbg_page_exception_breakpoint(const HANDLE process_handle)
{
    bool found = false;
    MEMORY_BASIC_INFORMATION mem_info = { 0 };

    if (executable_pages == NULL)
    {
        _page_exception_initial_enum(process_handle);
        if (executable_pages == NULL)
            return false;
    }

    // guard / NOACCESS on any module page
    PVOID  module_handle = NULL;
    SIZE_T size_of_image = 0;

    if (!NT_SUCCESS(DbgNtQueryVirtualMemory(
        process_handle,
        (PVOID)__adbg_page_exception_breakpoint,
        MemoryBasicInformation,
        &mem_info,
        sizeof(mem_info),
        NULL)))
    {
        _free_pages();
        return false;
    }

    module_handle = mem_info.AllocationBase;
    if (!module_handle) {
        _free_pages();
        return false;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_handle;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)module_handle + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            size_of_image = nt->OptionalHeader.SizeOfImage;
        }
    }

    if (size_of_image == 0) {
        _free_pages();
        return false;
    }

    size_t pageSize = PAGE_SIZE;
    BYTE* base = (BYTE*)module_handle;

    const DWORD exec_mask =
        PAGE_EXECUTE |
        PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY;

    for (size_t ofs = 0; ofs < size_of_image; ofs += pageSize)
    {
        SIZE_T return_length = 0;
        const NTSTATUS status = DbgNtQueryVirtualMemory(
            process_handle,
            base + ofs,
            MemoryBasicInformation,
            &mem_info,
            sizeof(mem_info),
            &return_length);

        if (status >= 0 && return_length >= sizeof(mem_info))
        {
            // only if this page is executable do we check guard
            if (mem_info.Protect & exec_mask)
            {
                if ((mem_info.Protect & PAGE_GUARD) ||
                    (mem_info.AllocationProtect & PAGE_GUARD))
                {
                    found = true;
                    break;
                }
            }
            // NOACCESS check applies to any page
            if (mem_info.Protect & PAGE_NOACCESS)
            {
                found = true;
                break;
            }
        }
    }

    // check our snapshot for lost exec perms
    if (!found)
    {
        for (size_t i = 0; i < executablePagesCount; ++i)
        {
            if (_test_delta_exec_loss(
                process_handle,
                executable_pages[i],
                &mem_info))
            {
                found = true;
                break;
            }
        }
    }

    _free_pages();
    return found;
}