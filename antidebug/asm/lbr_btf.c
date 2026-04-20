#include "lbr_btf.h"
#include "../core/syscall.h"

volatile BOOL g_debugger = FALSE;

LONG __stdcall _vectored_handler(PEXCEPTION_POINTERS exception_info) {
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // The kernel's int 01 (#DB) handler populates ExceptionInformation with the LBR From address
        // if LBR was enabled in DR7. The int 03 (#BP) handler does NOT do this. This is why using
        // icebp is essential for this technique

        // A debugger tracing this code will likely clear the LBR/BTF bits
        // in DR7 to perform its own single-stepping. This causes the CPU to not record the LBR data,
        // resulting in an empty ExceptionInformation array
        if (exception_info->ExceptionRecord->NumberParameters == 0) {
            g_debugger = TRUE;
        }
        else {
            // An advanced debugger might leave LBR enabled but still intercept
            // the exception. The act of trapping into the kernel and back out will pollute the LBR with
            // kernel-mode branch addresses. We can detect this by checking if the address is in user-space
            ULONG_PTR fromAddr = (ULONG_PTR)exception_info->ExceptionRecord->ExceptionInformation[0];
            if (fromAddr > (ULONG_PTR)0x7FFFFFFFFFFFFFFF) {
                g_debugger = TRUE;
            }
        }

        // past icebp
        exception_info->ContextRecord->Rip++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

inline static void _lbr_btf(const HANDLE process_handle, const HANDLE thread_handle) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    NTSTATUS status = 0;

    status = DbgNtGetContextThread(thread_handle, &ctx);
    if (status != 0) {
        return;
    }

    // bit 8 of DR7 maps to bit 0 of DebugCtl MSR (LBR - Last Branch Record)
    // bit 9 of DR7 maps to bit 1 of DebugCtl MSR (BTF - Branch Trap Flag)
    ctx.Dr7 |= (1ULL << 8) | (1ULL << 9);

    status = DbgNtSetContextThread(thread_handle, &ctx);
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

    memcpy(exec_mem, trigger_sequence, sizeof(trigger_sequence));
    void (*pfn_trigger)(void) = (void (*)(void))exec_mem;

    __try {
        pfn_trigger();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    region_size = 0;
    status = DbgNtFreeVirtualMemory(
        process_handle, 
        &exec_mem,          
        &region_size,      
        MEM_RELEASE
    );

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    status = DbgNtSetContextThread(thread_handle, &ctx);
    if (status == 0) {
        ctx.Dr7 &= ~((1ULL << 8) | (1ULL << 9));
        DbgNtSetContextThread(thread_handle, &ctx);
    }
}

bool __adbg_lbr(const HANDLE process_handle, const HANDLE thread_handle)
{
    const PVOID veh = AddVectoredExceptionHandler(1, _vectored_handler);
    if (!veh) {
        return false;
    }

    _lbr_btf(process_handle, thread_handle);

    RemoveVectoredExceptionHandler(veh);

    if (g_debugger) {
        return true;
    }

    return false;
}