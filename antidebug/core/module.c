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

static _force_inline int is_valid_range(size_t offset, size_t sz, size_t module_size) 
{
    return (sz > 0) && (offset < module_size) && (sz <= module_size - offset);
}

static _force_inline const char* cstr_from_rva(unsigned char* base, size_t module_size, DWORD rva) 
{
    if (!is_valid_range((size_t)rva, 1, module_size)) return NULL;

    const char* start = (const char*)(base + rva);
    const size_t remaining = module_size - (size_t)rva;

    if (memchr(start, '\0', remaining)) {
        return start;
    }
    return NULL;
}

static _force_inline int __wcsnicmp_ascii(const wchar_t* wstr, const char* str, USHORT wlen_bytes) 
{
    USHORT wchars = wlen_bytes / sizeof(wchar_t);
    for (USHORT i = 0; i < wchars; i++) {
        if (*str == '\0') return 1; // wstr is longer
        wchar_t wc = wstr[i];
        char c = *str;
        if (wc >= L'A' && wc <= L'Z') wc += L'a' - L'A';
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (wc != (wchar_t)c) return (int)wc - (int)c;
        str++;
    }
    return (*str == '\0') ? 0 : -1; // check if str has more chars
}

// manual implementation of GetModuleHandle
static _force_inline HMODULE __get_module_handle(const char* module_name) 
{
    PEB_T* peb = (PEB_T*)__readgsqword(0x60); // x64 PEB

    if (module_name == NULL) {
        return (HMODULE)peb->ImageBaseAddress;
    }

    PEB_LDR_DATA_T* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr != head) {
        LDR_DATA_TABLE_ENTRY_T* entry = (LDR_DATA_TABLE_ENTRY_T*)curr;
        if (entry->BaseDllName.Buffer != NULL) {
            if (__wcsnicmp_ascii(entry->BaseDllName.Buffer, module_name, entry->BaseDllName.Length) == 0) {
                return (HMODULE)entry->DllBase;
            }
        }
        curr = curr->Flink;
    }
    return NULL;
}

// manual implementation of GetProcAddress
void* __get_module(const char* module_name, const char* function_name) 
{
    if (!function_name) return NULL;

    HMODULE hModule = __get_module_handle(module_name);
    if (!hModule) return NULL;

    unsigned char* base = (unsigned char*)hModule;

    // validate DOS header safely without VirtualQuery
    const IMAGE_DOS_HEADER* dosHeader = (const IMAGE_DOS_HEADER*)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (dosHeader->e_lfanew < 0) return NULL;

    // e_lfanew -> NT headers
    size_t e_lfanew = (size_t)dosHeader->e_lfanew;
    const IMAGE_NT_HEADERS* ntHeaders = (const IMAGE_NT_HEADERS*)(base + e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    const size_t module_size = (size_t)ntHeaders->OptionalHeader.SizeOfImage;
    if (module_size == 0) return NULL;

    // check export data directory exists
    if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return NULL;

    const IMAGE_DATA_DIRECTORY* dd = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dd->VirtualAddress == 0 || dd->Size == 0) return NULL; // no exports?

    // validate export directory fits
    if (!is_valid_range((size_t)dd->VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), module_size)) return NULL;
    const IMAGE_EXPORT_DIRECTORY* exportDir = (const IMAGE_EXPORT_DIRECTORY*)(base + dd->VirtualAddress);

    const DWORD nameCount = exportDir->NumberOfNames;
    const DWORD funcCount = exportDir->NumberOfFunctions;

    const DWORD MAX_NAMES = 1u << 20; // absurdity check
    if (nameCount == 0 || nameCount > MAX_NAMES) return NULL;
    if (funcCount == 0 || funcCount > MAX_NAMES) return NULL;

    const DWORD addr_names = exportDir->AddressOfNames;
    const DWORD addr_funcs = exportDir->AddressOfFunctions;
    const DWORD addr_ord = exportDir->AddressOfNameOrdinals;

    if (!is_valid_range((size_t)addr_names, (size_t)nameCount * sizeof(DWORD), module_size)) return NULL;
    if (!is_valid_range((size_t)addr_funcs, (size_t)funcCount * sizeof(DWORD), module_size)) return NULL;
    if (!is_valid_range((size_t)addr_ord, (size_t)nameCount * sizeof(WORD), module_size)) return NULL;

    const DWORD* nameRvas = (const DWORD*)(base + addr_names);
    const DWORD* funcRvas = (const DWORD*)(base + addr_funcs);
    const WORD* ordinals = (const WORD*)(base + addr_ord);

    // binary search over names, export directory name array is lexically sorted
    DWORD lo = 0, hi = nameCount;
    while (lo < hi) {
        DWORD mid = lo + (hi - lo) / 2;
        DWORD midNameRva = nameRvas[mid];
        const char* midName = cstr_from_rva(base, module_size, midNameRva);

        if (!midName) {
            lo = hi; // corrupted string table
            break;
        }

        int cmp = strcmp(function_name, midName);
        if (cmp > 0) {
            lo = mid + 1;
        }
        else {
            hi = mid;
        }
    }

    if (lo < nameCount) {
        const char* candidateName = cstr_from_rva(base, module_size, nameRvas[lo]);
        if (candidateName && strcmp(function_name, candidateName) == 0) {
            const WORD nameOrdinal = ordinals[lo];
            if ((DWORD)nameOrdinal >= funcCount) return NULL;

            const DWORD funcRva = funcRvas[nameOrdinal];
            if (!is_valid_range((size_t)funcRva, 1, module_size)) return NULL;

            // found it
            return (void*)(base + funcRva);
        }
    }

    return NULL;
}