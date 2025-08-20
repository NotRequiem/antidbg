#include "ntldt.h"
#include "../core/syscall.h"

volatile BOOL g_ldtCheckPassed = FALSE;

// The LdtTargetFunction is no longer needed as its functionality is now
// dynamically generated within CheckNtSetLdtEntries.

bool CheckNtSetLdtEntries()
{
    // mov dword ptr [g_ldtCheckPassed], 1
    // retf
    unsigned char targetOpcodes[] = {
        0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [addr], 1
        0xCB                                                        // retf
    };

    // Patch the address of g_ldtCheckPassed into the machine code.
    *(DWORD_PTR*)&targetOpcodes[2] = (DWORD_PTR)&g_ldtCheckPassed;

    LPVOID pTargetFuncMem = VirtualAlloc(NULL, sizeof(targetOpcodes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetFuncMem) {
        return FALSE;
    }
    memcpy(pTargetFuncMem, targetOpcodes, sizeof(targetOpcodes));

    LDT_ENTRY ldtEntry = { 0 };
    const WORD selector = 0x07; // TI=0 (GDT), RPL=3. Bit 2=1 indicates LDT.
    DWORD_PTR base = (DWORD_PTR)pTargetFuncMem;

    ldtEntry.BaseLow = base & 0xFFFF;
    ldtEntry.HighWord.Bytes.BaseMid = (base >> 16) & 0xFF;
    ldtEntry.HighWord.Bytes.BaseHi = (base >> 24) & 0xFF;
    ldtEntry.LimitLow = 0xFFFF;
    ldtEntry.HighWord.Bits.Pres = 1;
    ldtEntry.HighWord.Bits.Dpl = 3;
    ldtEntry.HighWord.Bits.Sys = 0;
    ldtEntry.HighWord.Bits.Type = 0b1100; // 32-bit execute-only code segment
    ldtEntry.HighWord.Bits.Default_Big = 1;
    ldtEntry.HighWord.Bits.Granularity = 1;

    PULONG pEntry = (PULONG)&ldtEntry;
    ULONG entryLow = pEntry[0];
    ULONG entryHigh = pEntry[1];

    NTSTATUS status = DbgNtSetLdtEntries(selector, entryLow, entryHigh, 0, 0, 0);

    if (status >= 0) {
        // Far call opcode: 9A [offset] [selector]
        unsigned char farCallOpcodes[] = { 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        *(DWORD*)&farCallOpcodes[1] = 0; // Offset is 0
        *(WORD*)&farCallOpcodes[5] = selector;

        LPVOID pFarCallMem = VirtualAlloc(NULL, sizeof(farCallOpcodes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pFarCallMem) {
            memcpy(pFarCallMem, farCallOpcodes, sizeof(farCallOpcodes));
            void (*pFarCall)() = (void(*)())pFarCallMem;

            __try {
                pFarCall();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                g_ldtCheckPassed = FALSE;
            }
            VirtualFree(pFarCallMem, 0, MEM_RELEASE);
        }
    }

    VirtualFree(pTargetFuncMem, 0, MEM_RELEASE);
    return g_ldtCheckPassed;
}