#include "hasher.h"

typedef struct {
    HMODULE hMod;
    DWORD   textRVA;
    DWORD   textSize;
    uint32_t originalCrc;
} ModuleCRC;

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

static inline uint32_t __fastcall Crc32_Section(void* sectionBase, DWORD sectionSize)
{
    uint64_t crc = 0;
    BYTE* p = (BYTE*)sectionBase;
    size_t i, q = sectionSize / 8, r = sectionSize % 8;

    for (i = 0; i < q; i++, p += 8) {
        uint64_t chunk = *(uint64_t*)p;
        crc = _mm_crc32_u64(crc, chunk);
    }
    for (i = 0; i < r; i++, p++) {
        crc = _mm_crc32_u8((uint32_t)crc, *p);
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

    // allocate array to hold CRC info
    modCrcs = (ModuleCRC*)calloc(mCount, sizeof(ModuleCRC));
    if (!modCrcs) {
        return;
    }

    // for each module, find .text and compute initial CRC
    for (i = 0; i < mCount; i++) {
        DWORD rva, size;
        if (GetTextSectionInfo(mods[i], &rva, &size)) {
            BYTE* textBase = (BYTE*)mods[i] + rva;
            modCrcs[i].hMod = mods[i];
            modCrcs[i].textRVA = rva;
            modCrcs[i].textSize = size;
            modCrcs[i].originalCrc = Crc32_Section(textBase, size);
            //printf("Module[%u]=%p  CRC=0x%08X\n", i, mods[i], modCrcs[i].originalCrc);
        }
    }

    for (;;) {
        SleepEx(1000, FALSE);

        for (i = 0; i < mCount; i++) {
            if (modCrcs[i].hMod == NULL)
                continue;

            BYTE* textBase = (BYTE*)modCrcs[i].hMod + modCrcs[i].textRVA;
            DWORD  size = modCrcs[i].textSize;
            uint32_t crc = Crc32_Section(textBase, size);

            if (crc != modCrcs[i].originalCrc) {
                /*
                wchar_t name[MAX_PATH];
                if (GetModuleFileNameW(modCrcs[i].hMod, name, _countof(name)))
                    fwprintf(stderr, L"[!] Module tampered: %s\n", name);
                else
                    fprintf(stderr, "[!] Module at %p tampered\n", modCrcs[i].hMod);

                fprintf(stderr, "    original CRC=0x%08X  new CRC=0x%08X\n",
                    modCrcs[i].originalCrc, crc);
                */

                TerminateProcess(hProcess, 0);
            }
        }
    }

    // free(modCrcs);
}
