#include "hasher.h"
#include "syscall.h"

static inline BOOL __fastcall GetTextSectionInfo(HMODULE hMod, DWORD* rva, DWORD* size)
{
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt;
    IMAGE_SECTION_HEADER* sec;
    WORD                 i;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            *rva = sec->VirtualAddress;
            *size = sec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

static inline uint32_t __fastcall Crc32_Section(const HMODULE hMod, const DWORD sectionRVA, const DWORD sectionSize)
{
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) return 0;

    BYTE* base = (BYTE*)hMod;
    BYTE* sectionBase = base + sectionRVA;
    BYTE* sectionEnd = sectionBase + sectionSize;

    if ((BYTE*)sectionBase < (BYTE*)mi.lpBaseOfDll || sectionEnd >((BYTE*)mi.lpBaseOfDll + mi.SizeOfImage))
        return 0; 

    uint64_t crc = 0;
    BYTE* p = sectionBase;
    SIZE_T bytesLeft = sectionSize;

    while (bytesLeft >= 8) {
        uint64_t chunk;
        memcpy(&chunk, p, sizeof(chunk)); 
        // always_inline function '_mm_crc32_u64' requires target feature 'crc32', but would be inlined into function 'Crc32_Section' that is compiled without support for 'crc32'
        crc = _mm_crc32_u64(crc, chunk);
        p += 8; bytesLeft -= 8;
    }
    while (bytesLeft > 0) {
        uint8_t b;
        memcpy(&b, p, 1);
        crc = _mm_crc32_u8((uint32_t)crc, b);
        p++; bytesLeft--;
    }
    return (uint32_t)crc;
}

void StartMemoryTracker(const HANDLE hProcess)
{
    HMODULE       mods[1024];
    DWORD         cbNeeded, mCount;
    ModuleCRC* modCrcs;
    DWORD         i;

    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &cbNeeded)) {
        return;
    }
    mCount = cbNeeded / sizeof(HMODULE);

    modCrcs = (ModuleCRC*)calloc(mCount, sizeof(ModuleCRC));
    if (!modCrcs) {
        return;
    }

    for (i = 0; i < mCount; i++) {
        DWORD rva, size;
        if (GetTextSectionInfo(mods[i], &rva, &size)) {
            modCrcs[i].hMod = mods[i];
            modCrcs[i].textRVA = rva;
            modCrcs[i].textSize = size;

            modCrcs[i].originalCrc = Crc32_Section(mods[i], rva, size);

#ifdef _DEBUG
            printf("Module[%u]=%p  CRC=0x%08X\n", i, mods[i], modCrcs[i].originalCrc);
#endif
        }
    }

    for (;;) {
        const DWORD minDelayMs = 500;
        const DWORD maxDelayMs = 2000;
        const DWORD randomDelayMs = minDelayMs + (rand() % (maxDelayMs - minDelayMs + 1));

        LARGE_INTEGER delay = { 0 };
        const __int64 randomDelayMs64 = (__int64)randomDelayMs;
        const __int64 conversionFactor = 10000;
        const __int64 result = -(randomDelayMs64 * conversionFactor);

        delay.QuadPart = result;

        DbgNtDelayExecution(FALSE, &delay);

        for (i = 0; i < mCount; i++) {
            if (modCrcs[i].hMod == NULL)
                continue;

            uint32_t crc = Crc32_Section(modCrcs[i].hMod, modCrcs[i].textRVA, modCrcs[i].textSize);

            if (crc != 0 && crc != modCrcs[i].originalCrc) {
#ifdef _DEBUG
                wchar_t name[MAX_PATH];
                if (GetModuleFileNameW(modCrcs[i].hMod, name, _countof(name)))
                    fwprintf(stderr, L"[!] Module tampered: %s\n", name);
                else
                    fprintf(stderr, "[!] Module at %p tampered\n", modCrcs[i].hMod);

                fprintf(stderr, "    original CRC=0x%08X  new CRC=0x%08X\n",
                    modCrcs[i].originalCrc, crc);
#endif
                __fastfail(ERROR_STACK_BUFFER_OVERRUN);
            }
        }
    }

    // free(modCrcs);
}
