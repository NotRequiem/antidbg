#include "monitor.h"
#include "syscall.h"
#include "callback.h"
#include "debug.h"
#include "module.h"

typedef struct _UNICODE_STRING_T {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_T;

typedef struct _LDR_DATA_TABLE_ENTRY_T {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_T FullDllName;
    UNICODE_STRING_T BaseDllName;
} LDR_DATA_TABLE_ENTRY_T;

typedef struct _PEB_LDR_DATA_T {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA_T;

typedef struct _PEB_T {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    BYTE Reserved3[4];
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA_T* Ldr;
} PEB_T;

static inline bool __read_section(HMODULE module_handle, DWORD* rva, DWORD* size)
{
    __try {
        BYTE* base = (BYTE*)module_handle;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        IMAGE_NT_HEADERS* nt;
        IMAGE_SECTION_HEADER* sec;
        WORD i;

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
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
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

#if defined(__clang__) || defined(__GNUC__)
    __attribute__((__target__("crc32")))
#endif
//  __attribute__((__target__("sse4.2")))
static _force_inline uint32_t __hash_section(const HMODULE module_handle, const DWORD sectionRVA, const DWORD sectionSize)
{
    uint32_t crc_result = 0;

    __try {
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

        crc_result = (uint32_t)crc;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        crc_result = 0;
    }

    return crc_result;
}

#if defined(__clang__) || defined(__GNUC__)
    __attribute__((__target__("crc32")))
#endif
void __start_monitor(const HANDLE process_handle)
{
    HMODULE modules[1024] = { 0 };
    DWORD module_count = 0;
    module_crc* module_hashes;
    DWORD i;

    // we need to enumerate  loaded modules via the PEB loader list to avoid picking up transient section mappings created by __detect_hook
    PEB_T* peb = (PEB_T*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return;

    PEB_LDR_DATA_T* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head && module_count < _countof(modules)) {
        LDR_DATA_TABLE_ENTRY_T* entry = (LDR_DATA_TABLE_ENTRY_T*)curr;
        if (entry->DllBase != NULL) {
            modules[module_count++] = (HMODULE)entry->DllBase;
        }
        curr = curr->Flink;
    }

    if (module_count == 0) return;

    module_hashes = (module_crc*)calloc(module_count, sizeof(module_crc));
    if (!module_hashes) return;

    for (i = 0; i < module_count; i++) {
        DWORD rva, size;
        if (__read_section(modules[i], &rva, &size)) {
            module_hashes[i].module_handle = modules[i];
            module_hashes[i].text_rva = rva;
            module_hashes[i].text_size = size;
            module_hashes[i].original_crc = __hash_section(modules[i], rva, size);
        }
    }

    _enable_privilege(L"SeSystemtimePrivilege", process_handle);

    HANDLE time_slip_event = NULL;
    bool time_slip_active = false;
    OBJECT_ATTRIBUTES object_attributes = { 0 };
    object_attributes.Length = sizeof(OBJECT_ATTRIBUTES);

    NTSTATUS status = DbgNtCreateEvent(&time_slip_event, EVENT_ALL_ACCESS, &object_attributes, SynchronizationEvent, FALSE);

    if (NT_SUCCESS(status)) {
        if (NT_SUCCESS(DbgNtSetSystemInformation((SYSTEM_INFORMATION_CLASS)SystemTimeSlipInformation, &time_slip_event, sizeof(time_slip_event)))) {
            time_slip_active = true;
        }
        else {
            DbgNtClose(time_slip_event);
            time_slip_event = NULL;
        }
    }

    for (;;) {
        if (!__set_callback(&g_callback_page, process_handle)) {
            __log("Instrumentation Callback integrity cannot be verified. Triggering fastfail.");
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }

        for (i = 0; i < module_count; i++) {
            if (module_hashes[i].module_handle == NULL) continue;

            const uint32_t crc = __hash_section(module_hashes[i].module_handle, module_hashes[i].text_rva, module_hashes[i].text_size);

            if (crc != 0 && crc != module_hashes[i].original_crc) {
                free(module_hashes);
                __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
            }
        }

        LARGE_INTEGER delay = { 0 };
        delay.QuadPart = -20 * 10000;

        if (time_slip_active && time_slip_event) {
            status = DbgNtWaitForSingleObject(time_slip_event, FALSE, &delay);
            if (status == 0x00000000L) {
                __log("[!] Wait satisfied illegally. Time slip event triggered?");
            }
        }
        else {
            DbgNtDelayExecution(FALSE, &delay);
        }

        if (!__detect_callback(g_callback_page.base, g_callback_page.size, process_handle)) {
            __log("[!] Instrumentation callback tampering detected");
            __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
        }
    }
}