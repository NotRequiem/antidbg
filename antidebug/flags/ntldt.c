#include "ntldt.h"
#include "../core/syscall.h"

volatile bool g_ldtCheckPassed = false;

bool CheckNtSetLdtEntries()
{
    // with BOOL it would be: mov dword ptr [addr], 1 (0xC7 0x05 [addr] 01 00 00 00)
    // right now is: mov byte ptr [addr], 1  (0xC6 0x05 [addr] 01)
    unsigned char targetOpcodes[] = {
       0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, // mov byte ptr [addr], 1 (addr is a 4-byte placeholder)
       0x01,                               // The immediate value to move (1)
       0xCB                                // retf (far return)
    };

    // instead of doing *(DWORD_PTR*)&targetOpcodes[2] = (DWORD_PTR)&g_ldtCheckPassed; i do:
    *(DWORD*)&targetOpcodes[2] = (DWORD)(DWORD_PTR)&g_ldtCheckPassed;
    /// this prevents a buffer overrun on 64 bit builds where DWORD_PTR is 8 bytes

    const size_t targetOpcodesSize = sizeof(targetOpcodes);
    LPVOID pTargetFuncMem = VirtualAlloc(NULL, targetOpcodesSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetFuncMem) {
        return false;
    }
    memcpy_s(pTargetFuncMem, targetOpcodesSize, targetOpcodes, targetOpcodesSize);

    LDT_ENTRY ldtEntry = { 0 };
    const WORD selector = 0x07; // TI=0 (GDT), RPL=3. Bit 2=1 indicates LDT
    DWORD_PTR base = (DWORD_PTR)pTargetFuncMem;

    ldtEntry.BaseLow = base & 0xFFFF;
    ldtEntry.HighWord.Bytes.BaseMid = (base >> 16) & 0xFF;
    ldtEntry.HighWord.Bytes.BaseHi = (base >> 24) & 0xFF;
    ldtEntry.LimitLow = 0xFFFF;
    ldtEntry.HighWord.Bits.Pres = 1;        // present
    ldtEntry.HighWord.Bits.Dpl = 3;         // descriptor Privilege Level
    ldtEntry.HighWord.Bits.Sys = 0;         // code or data segment
    ldtEntry.HighWord.Bits.Type = 0b1100;    // 32-bit execute-only code segment
    ldtEntry.HighWord.Bits.Default_Big = 1; // 32-bit segment
    ldtEntry.HighWord.Bits.Granularity = 1; // page granularity

    PULONG pEntry = (PULONG)&ldtEntry;
    ULONG entryLow = pEntry[0];
    ULONG entryHigh = pEntry[1];

    NTSTATUS status = DbgNtSetLdtEntries(selector, entryLow, entryHigh, 0, 0, 0);

    if (status >= 0) {
        // far call opcode: 9A [offset] [selector]
        unsigned char farCallOpcodes[] = { 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        *(DWORD*)&farCallOpcodes[1] = 0; // Offset is 0 as it's relative to the segment base
        *(WORD*)&farCallOpcodes[5] = selector;

        const size_t farCallOpcodesSize = sizeof(farCallOpcodes);
        LPVOID pFarCallMem = VirtualAlloc(NULL, farCallOpcodesSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pFarCallMem) {
            memcpy_s(pFarCallMem, farCallOpcodesSize, farCallOpcodes, farCallOpcodesSize);
            void (*pFarCall)() = (void(*)())pFarCallMem;

            __try {
                pFarCall();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                g_ldtCheckPassed = false;
            }
            VirtualFree(pFarCallMem, 0, MEM_RELEASE);
        }
    }

    VirtualFree(pTargetFuncMem, 0, MEM_RELEASE);
    return g_ldtCheckPassed;
}