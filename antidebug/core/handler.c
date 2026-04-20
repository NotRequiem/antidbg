#include "handler.h"
#include "module.h"
#include "syscall.h"
#include "debug.h"

static _force_inline bool __detect_hook(const char* module_name, const char* function_name, const HANDLE process_handle)
{
    PVOID memory_function = (PVOID)__get_module(module_name, function_name);
    if (!memory_function) return false;

    // some apis like kernel32!IsDebuggerPresent forwards to kernelbase.dll
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if (!NT_SUCCESS(DbgNtQueryVirtualMemory(process_handle, memory_function, MemoryBasicInformation, &mbi, sizeof(mbi), NULL))) {
        return false;
    }
    HMODULE actual_module = (HMODULE)mbi.AllocationBase;

    BYTE buffer[sizeof(UNICODE_STRING) + MAX_PATH * sizeof(WCHAR)] = { 0 };
    PUNICODE_STRING mapped_filename = (PUNICODE_STRING)buffer;

    if (!NT_SUCCESS(DbgNtQueryVirtualMemory(process_handle, actual_module, MemoryMappedFilenameInformation, mapped_filename, sizeof(buffer), NULL))) {
        return false;
    }

    OBJECT_ATTRIBUTES object_attributes = { sizeof(OBJECT_ATTRIBUTES), NULL, mapped_filename, OBJ_CASE_INSENSITIVE, NULL, NULL };
    IO_STATUS_BLOCK io_status = { 0 };
    HANDLE file_handle = NULL;

    // open clean file directly from disk
    if (!NT_SUCCESS(DbgNtOpenFile(&file_handle, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE, &object_attributes, &io_status,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)))
    {
        return false;
    }

    HANDLE section_handle = NULL;
    // SEC_IMAGE tells the kernel to map it as an executable image
    NTSTATUS status = DbgNtCreateSection(&section_handle, SECTION_MAP_READ | SECTION_MAP_EXECUTE, NULL, NULL,
        PAGE_EXECUTE_READ, SEC_IMAGE, file_handle);
    DbgNtClose(file_handle);
    if (!NT_SUCCESS(status)) return false;

    PVOID mapped_base = NULL;
    SIZE_T view_size = 0;
    // ViewShare = 1
    status = DbgNtMapViewOfSection(section_handle, process_handle, &mapped_base, 0, 0, NULL, &view_size, 1, 0, PAGE_EXECUTE_READ);
    DbgNtClose(section_handle);
    if (!NT_SUCCESS(status)) return false;

    // calculate true RVA
    SIZE_T rva = (SIZE_T)((ULONG_PTR)memory_function - (ULONG_PTR)actual_module);

    // find the corresponding address in clean mapped disk image
    PVOID pDiskFunc = (PVOID)((ULONG_PTR)mapped_base + rva);

    // 0xE9 (JMP), 0xCC (INT 3), 0xC3 (RET), etc
    const bool hooked = (memcmp(memory_function, pDiskFunc, 16) != 0);

    DbgNtUnmapViewOfSection(process_handle, mapped_base);

    return hooked;
}

LONG CALLBACK __global_handler(PEXCEPTION_POINTERS exception_info) 
{
    if (!exception_info || !exception_info->ContextRecord || !exception_info->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        const PCONTEXT ctx = exception_info->ContextRecord;
        if (ctx->Dr0 || ctx->Dr1 || ctx->Dr2 || ctx->Dr3) {
            __log("[!] Hardware debug registers detected");
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }
    }

    __try {
        if (__detect_hook("ntdll.dll", "KiUserExceptionDispatcher", (HANDLE)-1)) {
            __log("[!] Hook detected on KiUserExceptionDispatcher");
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return EXCEPTION_CONTINUE_SEARCH;
}
