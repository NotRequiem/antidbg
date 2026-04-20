#include "monitor.h"
#include "syscall.h"
#include "callback.h"
#include "debug.h"
#include "module.h"

typedef struct _MEMORY_SECTION_NAME {
    UNICODE_STRING SectionFileName;
} MEMORY_SECTION_NAME, * PMEMORY_SECTION_NAME;

static inline bool __read_section(HMODULE module_handle, DWORD* rva, DWORD* size)
{
    BYTE* base = (BYTE*)module_handle;
    IMAGE_DOS_HEADER*     dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS*     nt;
    IMAGE_SECTION_HEADER* sec;
    WORD                  i;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            *rva = sec->VirtualAddress;
            *size = sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static inline void _enable_privilege(LPCWSTR privilege_name, const HANDLE process_handle) {
    HANDLE token_handle;
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;

    if (!OpenProcessToken(process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) {
        return;
    }

    if (!LookupPrivilegeValueW(NULL, privilege_name, &luid)) {
        DbgNtClose(token_handle);
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        DbgNtClose(token_handle);
        return;
    }

    DbgNtClose(token_handle);
    return;
}

static _force_inline uint32_t __hash_section(const HMODULE module_handle, const DWORD sectionRVA, const DWORD sectionSize)
#if (__clang__ || __GNUC__)
__attribute__((__target__("crc32")))
#endif
{
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_handle;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module_handle + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return 0;

    BYTE* base = (BYTE*)module_handle;
    BYTE* sectionBase = base + sectionRVA;
    BYTE* sectionEnd = sectionBase + sectionSize;

    if ((BYTE*)sectionBase < base || sectionEnd >(base + nt_headers->OptionalHeader.SizeOfImage))
        return 0;

    uint64_t crc = 0;
    BYTE* p = sectionBase;
    SIZE_T bytesLeft = sectionSize;

    while (bytesLeft >= 8) {
        uint64_t chunk = *(uint64_t*)p;
        crc = _mm_crc32_u64(crc, chunk);
        p += 8; bytesLeft -= 8;
    }
    while (bytesLeft > 0) {
        uint8_t b = *p;
        crc = _mm_crc32_u8((uint32_t)crc, b);
        p++; bytesLeft--;
    }

    return (uint32_t)crc;
}

void __start_monitor(const HANDLE process_handle)
{
    HMODULE       modules[1024] = { 0 };
    DWORD         module_count = 0;
    module_crc* module_hashes;
    DWORD         i;

    PVOID base_address = NULL;
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    while (NT_SUCCESS(DbgNtQueryVirtualMemory(process_handle, base_address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL))) {
        if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT && mbi.BaseAddress == mbi.AllocationBase) {
            if (module_count < _countof(modules)) {
                modules[module_count++] = (HMODULE)mbi.AllocationBase;
            }
            else {
                break;
            }
        }
        base_address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    if (module_count == 0) {
        __log_error("DbgNtQueryVirtualMemory mapping failed");
        return;
    }

    module_hashes = (module_crc*)calloc(module_count, sizeof(module_crc));
    if (!module_hashes) {
        __log("calloc failed for module_hashes");
        return;
    }

    for (i = 0; i < module_count; i++) {
        DWORD rva, size;
        if (__read_section(modules[i], &rva, &size)) {
            module_hashes[i].module_handle = modules[i];
            module_hashes[i].text_rva = rva;
            module_hashes[i].text_size = size;

            module_hashes[i].original_crc = __hash_section(modules[i], rva, size);
            __log("[*] Registered module %u at virtual address %p for protection; hash=0x%08X", i, modules[i], module_hashes[i].original_crc);
        }
    }

    _enable_privilege(L"SeSystemtimePrivilege", process_handle);

    // same as doing const HANDLE hTimeSlipEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    HANDLE time_slip_event = NULL;
    OBJECT_ATTRIBUTES object_attributes = { 0 };

    object_attributes.Length = sizeof(OBJECT_ATTRIBUTES);

    NTSTATUS status = DbgNtCreateEvent(
        &time_slip_event,
        EVENT_ALL_ACCESS,
        &object_attributes,
        SynchronizationEvent,
        FALSE
    );

    status = DbgNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)SystemTimeSlipInformation, &time_slip_event, sizeof(time_slip_event));
    if (status != 0) { // we dont care if EnablePrivilege or CreateEvent previously fails, we check everything here
        DbgNtClose(time_slip_event);
    }

    for (;;) {
        for (i = 0; i < module_count; i++) {
            // aggresively re-set our legit callback because any memory inspection check to confirm our callback is intact (using NtReadVirtualMemory or similar)
            // can be bypassed by the malicious callback itself by returning spoofed results in RAX
            // __set_callback also issues a direct syscall, but the malicious instrumentation callback can't intercept the work done by the kernel before us issuing this callback
            // they could re-set their callback immediately after detecting this, which is why the re-set it's inside a tight infinite loop in this .text module hasher
            if (!__set_callback(&g_callback_page, process_handle)) {
                __log("Instrumentation Callback integrity cannot be verified. Triggering fastfail.");
                __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
            }

            if (module_hashes[i].module_handle == NULL)
                continue;

            const uint32_t crc = __hash_section(module_hashes[i].module_handle, module_hashes[i].text_rva, module_hashes[i].text_size);

            if (crc != 0 && crc != module_hashes[i].original_crc) {
            #ifdef _DEBUG
                BYTE buffer[sizeof(MEMORY_SECTION_NAME) + MAX_PATH * sizeof(WCHAR)] = { 0 };
                PMEMORY_SECTION_NAME section_name = (PMEMORY_SECTION_NAME)buffer;

                if (NT_SUCCESS(DbgNtQueryVirtualMemory(process_handle, module_hashes[i].module_handle, 2, section_name, sizeof(buffer), NULL))) {
                    section_name->SectionFileName.Buffer[section_name->SectionFileName.Length / sizeof(WCHAR)] = L'\0';
                    __log("[!] Module tampered: %ls", section_name->SectionFileName.Buffer);
                }
                else {
                    __log("[!] Module at %p tampered", module_hashes[i].module_handle);
                }

                __log("    original CRC=0x%08X  new CRC=0x%08X", module_hashes[i].original_crc, crc);
            #endif
                free(module_hashes);
                __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
            }
        }

        LARGE_INTEGER timeout = { 0 };
        timeout.QuadPart = -20 * 10000;
        status = DbgNtWaitForSingleObject(
            time_slip_event,
            FALSE,
            &timeout
        );

        // same as STATUS_SUCCESS, WAIT_OBJECT_0 on WaitForSingleObject
        if (status == 0x00000000L) { // ((((DWORD)0x00000000L)) + 0)
            __log("[!] Wait satisfied illegally. Time slip event triggered? Fastfailing.");
            DbgNtClose(time_slip_event);
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }

        if (!__detect_callback(g_callback_page.base, g_callback_page.size, process_handle)) {
            __log("[!] Instrumentation callback tampering detected");
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }
    }
}
