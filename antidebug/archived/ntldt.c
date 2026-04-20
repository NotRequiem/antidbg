#include "ntldt.h"
#include "../core/syscall.h"

// for x86 legacy segment behavior only

volatile bool g_ldt_check_passed = false;

bool __adbg_ldt_entries(const HANDLE process_handle)
{
    // with BOOL it would be: mov dword ptr [addr], 1 (0xC7 0x05 [addr] 01 00 00 00)
    // right now is: mov byte ptr [addr], 1  (0xC6 0x05 [addr] 01)
    unsigned char opcodes[] = {
       0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, // mov byte ptr [addr], 1 (addr is a 4-byte placeholder)
       0x01,                               // The immediate value to move (1)
       0xCB                                // retf (far return)
    };

    // instead of doing *(DWORD_PTR*)&targetOpcodes[2] = (DWORD_PTR)&g_ldtCheckPassed; i do:
    *(DWORD*)&opcodes[2] = (DWORD)(DWORD_PTR)&g_ldt_check_passed;
    // prevents a buffer overrun on 64 bit builds where DWORD_PTR is 8 bytes

    const size_t opcodes_size = sizeof(opcodes);
    PVOID target_function_memory = NULL;
    SIZE_T region_size = opcodes_size;
    ULONG old_protection = 0;

    if (DbgNtAllocateVirtualMemory(process_handle, &target_function_memory, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) < 0 || !target_function_memory) {
        return false;
    }

    memcpy(target_function_memory, opcodes, opcodes_size);

    PVOID protect_addr = target_function_memory;
    SIZE_T protect_size = opcodes_size;
    DbgNtProtectVirtualMemory(process_handle, &protect_addr, &protect_size, PAGE_EXECUTE_READ, &old_protection);

    DbgNtFlushInstructionCache(process_handle, target_function_memory, (ULONG)opcodes_size);

    LDT_ENTRY ldt = { 0 };
    const WORD selector = 0x07; // TI=0 (GDT), RPL=3. Bit 2=1 indicates LDT
    DWORD_PTR base = (DWORD_PTR)target_function_memory;

    ldt.BaseLow = base & 0xFFFF;
    ldt.HighWord.Bytes.BaseMid = (base >> 16) & 0xFF;
    ldt.HighWord.Bytes.BaseHi = (base >> 24) & 0xFF;
    ldt.LimitLow = 0xFFFF;
    ldt.HighWord.Bits.Pres = 1;        // present
    ldt.HighWord.Bits.Dpl = 3;         // descriptor Privilege Level
    ldt.HighWord.Bits.Sys = 0;         // code or data segment
    ldt.HighWord.Bits.Type = 0b1100;    // 32-bit execute-only code segment
    ldt.HighWord.Bits.Default_Big = 1; // 32-bit segment
    ldt.HighWord.Bits.Granularity = 1; // page granularity

    PULONG p_entry = (PULONG)&ldt;
    ULONG entry_low = p_entry[0];
    ULONG entry_high = p_entry[1];

    const NTSTATUS status = DbgNtSetLdtEntries(selector, entry_low, entry_high, 0, 0, 0);

    if (status >= 0) {
        // far call opcode: 9A [offset] [selector]
        unsigned char farcall_stub[] = { 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        *(DWORD*)&farcall_stub[1] = 0; // Offset is 0 as it's relative to the segment base
        *(WORD*)&farcall_stub[5] = selector;

        const size_t farcall_size = sizeof(farcall_stub);
        PVOID farcall_memory = NULL;
        SIZE_T farcall_region = farcall_size;

        if (DbgNtAllocateVirtualMemory(process_handle, &farcall_memory, 0, &farcall_region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) >= 0 && farcall_memory) {
            memcpy(farcall_memory, farcall_stub, farcall_size);

            PVOID far_protect_addr = farcall_memory;
            SIZE_T far_protect_size = farcall_size;
            DbgNtProtectVirtualMemory(process_handle, &far_protect_addr, &far_protect_size, PAGE_EXECUTE_READ, &old_protection);

            DbgNtFlushInstructionCache(process_handle, farcall_memory, (ULONG)farcall_size);
            void (*farcall_pointer)() = (void(*)())farcall_memory;

            __try {
                farcall_pointer();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                g_ldt_check_passed = false;
            }

            SIZE_T free_size = 0;
            DbgNtFreeVirtualMemory(process_handle, &farcall_memory, &free_size, MEM_RELEASE);
        }
    }

    SIZE_T free_size = 0;
    DbgNtFreeVirtualMemory(process_handle, &target_function_memory, &free_size, MEM_RELEASE);
    return g_ldt_check_passed;
}