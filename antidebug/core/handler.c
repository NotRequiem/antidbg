#include "handler.h"
#include "module.h"
#include "syscall.h"
#include "debug.h"

static _force_inline bool __detect_hook(const char* module_name, const char* function_name, const HANDLE process_handle)
{
    HANDLE current_process = (HANDLE)-1;

    // get local address for exact RVA 
    PVOID local_function = (PVOID)__get_module(module_name, function_name);
    if (!local_function) return false;

    MEMORY_BASIC_INFORMATION local_mbi = { 0 };
    if (!NT_SUCCESS(DbgNtQueryVirtualMemory(current_process, local_function, MemoryBasicInformation, &local_mbi, sizeof(local_mbi), NULL))) {
        return false;
    }
    HMODULE local_module = (HMODULE)local_mbi.AllocationBase;
    SIZE_T rva = (SIZE_T)((ULONG_PTR)local_function - (ULONG_PTR)local_module);

    // identify where this module resides
    PVOID remote_function = (PVOID)((ULONG_PTR)local_module + rva);

    MEMORY_BASIC_INFORMATION remote_mbi = { 0 };
    if (!NT_SUCCESS(DbgNtQueryVirtualMemory(process_handle, remote_function, MemoryBasicInformation, &remote_mbi, sizeof(remote_mbi), NULL))) {
        return false;
    }
    HMODULE remote_module = (HMODULE)remote_mbi.AllocationBase;

    // actual file path from the target's memory
    BYTE buffer[sizeof(UNICODE_STRING) + MAX_PATH * sizeof(WCHAR)] = { 0 };
    PUNICODE_STRING mapped_filename = (PUNICODE_STRING)buffer;

    if (!NT_SUCCESS(DbgNtQueryVirtualMemory(process_handle, remote_module, MemoryMappedFilenameInformation, mapped_filename, sizeof(buffer), NULL))) {
        return false;
    }

    OBJECT_ATTRIBUTES object_attributes = { sizeof(OBJECT_ATTRIBUTES), NULL, mapped_filename, OBJ_CASE_INSENSITIVE, NULL, NULL };
    IO_STATUS_BLOCK io_status = { 0 };
    HANDLE file_handle = NULL;

    // clean file directly from disk
    if (!NT_SUCCESS(DbgNtOpenFile(&file_handle, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE, &object_attributes, &io_status,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)))
    {
        return false;
    }

    HANDLE section_handle = NULL;
    NTSTATUS status = DbgNtCreateSection(&section_handle, SECTION_MAP_READ | SECTION_MAP_EXECUTE, NULL, NULL,
        PAGE_EXECUTE_READ, SEC_IMAGE, file_handle);
    DbgNtClose(file_handle);
    if (!NT_SUCCESS(status)) return false;

    PVOID mapped_base = NULL;
    SIZE_T view_size = 0;

    // map view in our process
    status = DbgNtMapViewOfSection(section_handle, current_process, &mapped_base, 0, 0, NULL, &view_size, 1, 0, PAGE_EXECUTE_READ);
    DbgNtClose(section_handle);
    if (!NT_SUCCESS(status)) return false;

    // dynamically resolve the exact function size
    DWORD function_size = 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped_base;
    PIMAGE_NT_HEADERS nt = NULL;

    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)mapped_base + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            DWORD pdata_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            DWORD pdata_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

            // try to find it in .pdata (exception directory)
            if (pdata_rva && pdata_size) {
                PRUNTIME_FUNCTION pdata = (PRUNTIME_FUNCTION)((ULONG_PTR)mapped_base + pdata_rva);
                DWORD num_functions = pdata_size / sizeof(RUNTIME_FUNCTION);

                for (DWORD i = 0; i < num_functions; i++) {
                    if (pdata[i].BeginAddress == (DWORD)rva) {
                        function_size = pdata[i].EndAddress - pdata[i].BeginAddress;
                        break;
                    }
                }
            }
        }
    }

    PBYTE disk_bytes = (PBYTE)((ULONG_PTR)mapped_base + rva);

    // if size is still 0, it's a leaf function (like ZwRaiseException), scan forward for the RET byte
    if (function_size == 0) {
        for (DWORD i = 0; i < 64; i++) {
            if (disk_bytes[i] == 0xC3) {
                function_size = i + 1;
                break;
            }
        }
        if (function_size == 0) function_size = 16; // strict fallback
    }

    // limit size to prevent buffer overflow
    if (function_size > 8192) function_size = 8192;

    // prevents stack overflow in this thread
    PVOID heap_memory = NULL;
    SIZE_T alloc_size = 16384; // 8192 for reloc_mask + 8192 for live_bytes
    if (!NT_SUCCESS(DbgNtAllocateVirtualMemory(current_process, &heap_memory, 0, &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        DbgNtUnmapViewOfSection(current_process, mapped_base);
        return false;
    }

    // 0 means compare the byte, 1 means skip the byte (it was modified by the OS loader)
    PBYTE reloc_mask = (PBYTE)heap_memory;
    PBYTE live_bytes = (PBYTE)heap_memory + 8192;

    // parse the base relocation table to build the mask
    if (nt) {
        DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (reloc_rva && reloc_size) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)mapped_base + reloc_rva);
            DWORD reloc_end = (DWORD)((ULONG_PTR)reloc + reloc_size);

            while ((ULONG_PTR)reloc < (ULONG_PTR)reloc_end && reloc->SizeOfBlock > 0) {
                DWORD page_rva = reloc->VirtualAddress;

                // only process relocation blocks that overlap our target function
                if ((unsigned long long)(page_rva) + 4096 >= rva && page_rva <= rva + function_size) {
                    DWORD num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    PWORD entries = (PWORD)((ULONG_PTR)reloc + sizeof(IMAGE_BASE_RELOCATION));

                    for (DWORD i = 0; i < num_entries; i++) {
                        WORD entry = entries[i];
                        WORD type = entry >> 12;
                        WORD offset = entry & 0xFFF;
                        DWORD entry_rva = page_rva + offset;

                        // if this specific relocation falls inside our function bounds
                        if (entry_rva >= rva && entry_rva < rva + function_size) {
                            DWORD func_offset = entry_rva - (DWORD)rva;

                            // mark these specific bytes as "do not compare"
                            if (type == IMAGE_REL_BASED_DIR64) {
                                for (int b = 0; b < 8 && (func_offset + b) < function_size; b++) reloc_mask[func_offset + b] = 1;
                            }
                            else if (type == IMAGE_REL_BASED_HIGHLOW) {
                                for (int b = 0; b < 4 && (func_offset + b) < function_size; b++) reloc_mask[func_offset + b] = 1;
                            }
                        }
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // live active bytes from the target process
    bool hooked = false;
    SIZE_T bytes_read = 0;

    if (NT_SUCCESS(DbgNtReadVirtualMemory(process_handle, remote_function, live_bytes, function_size, &bytes_read)) && bytes_read == function_size) {

        // byte-by-byte comparison, ignoring relocated bytes
        for (DWORD i = 0; i < function_size; i++) {
            if (reloc_mask[i] == 1) continue; // skip OS modified pointers

            if (live_bytes[i] != disk_bytes[i]) {
                hooked = true;
                break;
            }
        }
    }

    DbgNtUnmapViewOfSection(current_process, mapped_base);

    alloc_size = 0; 
    DbgNtFreeVirtualMemory(current_process, &heap_memory, &alloc_size, MEM_RELEASE);

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
        if (__detect_hook("ntdll.dll", "ZwRaiseException", (HANDLE)-1)) {
            __log("[!] Hook detected on ZwRaiseException");
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }
        if (__detect_hook("ntdll.dll", "RtlRestoreContext", (HANDLE)-1)) {
            __log("[!] Hook detected on RtlRestoreContext");
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }
        if (__detect_hook("ntdll.dll", "RtlRaiseStatus", (HANDLE)-1)) {
            __log("[!] Hook detected on RtlRaiseStatus");
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return EXCEPTION_CONTINUE_SEARCH;
}
