#include "lbr_btf.h"
#include "../core/syscall.h"

volatile BOOL g_debugger = FALSE;
volatile BOOL g_veh_invoked = FALSE;
PVOID g_lbr_buffer = NULL;
SIZE_T g_lbr_size = 0;

LONG __stdcall _vectored_handler(PEXCEPTION_POINTERS exception_info) {
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        const ULONG_PTR rip = exception_info->ContextRecord->Rip;
        if (g_lbr_buffer && rip >= (ULONG_PTR)g_lbr_buffer && rip < ((ULONG_PTR)g_lbr_buffer + g_lbr_size)) {
            g_veh_invoked = TRUE;
            uint8_t current_byte = *(uint8_t*)rip;

            if (current_byte != 0xC3 && current_byte != 0xF1) {
                g_debugger = TRUE;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (exception_info->ExceptionRecord->NumberParameters >= 2) {
                const ULONG_PTR info_from = exception_info->ExceptionRecord->ExceptionInformation[0];
                const ULONG_PTR info_to = exception_info->ExceptionRecord->ExceptionInformation[1];

                if ((LONG_PTR)info_from < 0 || (LONG_PTR)info_to < 0) {
                    g_debugger = TRUE;
                }
            }

            if (current_byte == 0xF1) { // icebp
                exception_info->ContextRecord->Rip++;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else if (current_byte == 0xC3) { // ret
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

inline static void _lbr_btf(const HANDLE process_handle) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    NTSTATUS status = 0;

    const HANDLE current_thread = (HANDLE)(LONG_PTR)-2; // must be this thread and not passed from __adbg
    status = DbgNtGetContextThread(current_thread, &ctx);
    if (status != 0) {
        return;
    }

    // bit 8 of DR7 maps to bit 0 of DebugCtl MSR (LBR - Last Branch Record)
    // bit 9 of DR7 maps to bit 1 of DebugCtl MSR (BTF - Branch Trap Flag)
    ctx.Dr7 |= (1ULL << 8) | (1ULL << 9);

    status = DbgNtSetContextThread(current_thread, &ctx);
    if (status != 0) {
        return;
    }

    const unsigned char trigger_sequence[] = {
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0x48, 0x83, 0xF8, 0x05,                   // cmp rax, 5
        0x74, 0x03,                               // je branch_target
        0x48, 0x31, 0xDB,                         // xor rbx, rbx
        // branch_target:
        0x9C,                                     // pushfq
        0x48, 0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, // or qword ptr[rsp], 0x100 (TF)
        0x9D,                                     // popfq
        0xF1,                                     // icebp
        0xC3                                      // ret
    };

    PVOID exec_mem = NULL;
    SIZE_T region_size = sizeof(trigger_sequence);

    status = DbgNtAllocateVirtualMemory(
        process_handle,
        &exec_mem,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (status != 0) {
        return;
    }

    g_lbr_buffer = exec_mem;
    g_lbr_size = region_size;

    memcpy(exec_mem, trigger_sequence, sizeof(trigger_sequence));
    void (*pfn_trigger)(void) = (void (*)(void))exec_mem;

    __try {
        pfn_trigger();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    g_lbr_buffer = NULL;
    g_lbr_size = 0;

    region_size = 0;
    status = DbgNtFreeVirtualMemory(
        process_handle,
        &exec_mem,
        &region_size,
        MEM_RELEASE
    );

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    status = DbgNtGetContextThread(current_thread, &ctx);
    if (status == 0) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            g_debugger = TRUE;
        }
        if (!(ctx.Dr7 & (1ULL << 8))) {
            g_debugger = TRUE;
        }
        if (!(ctx.Dr7 & (1ULL << 9))) {
            g_debugger = TRUE;
        }
        ctx.Dr7 &= ~((1ULL << 8) | (1ULL << 9));
        DbgNtSetContextThread(current_thread, &ctx);
    }
}

bool __adbg_lbr(const HANDLE process_handle)
{
    g_debugger = FALSE;
    g_veh_invoked = FALSE;
    const PVOID veh = AddVectoredExceptionHandler(1, _vectored_handler);
    if (!veh) {
        return false;
    }

    _lbr_btf(process_handle);

    RemoveVectoredExceptionHandler(veh);

    if (!g_veh_invoked) {
        g_debugger = TRUE;
    }

    if (g_debugger) {
        return true;
    }

    return false;
}
