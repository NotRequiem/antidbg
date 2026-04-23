#include "instcnt.h"
#include "..\core\syscall.h"

struct {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    ULONG_PTR ClientId[2];
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} tbi = { 0 };

static LONG __stdcall _inst_count_excp_handler(PEXCEPTION_POINTERS exception_info)
{
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        // increment instruction counter
        exception_info->ContextRecord->Rax += 1;

        // increment RIP to pass control to the next instruction (skipping the 1-byte NOP)
        exception_info->ContextRecord->Rip += 1;

        // clear the DR6 status bits so subsequent HW BPs trigger properly
        exception_info->ContextRecord->Dr6 &= ~(0xF);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool __adbg_instruction_count(const HANDLE process_handle)
{
    /*
        48 31 C0          xor rax, rax       ; initialize instruction counter to 0
        90                nop                ; HWBP 0 (offset 3)
        90                nop                ; HWBP 1 (offset 4)
        90                nop                ; HWBP 2 (offset 5)
        90                nop                ; HWBP 3 (offset 6)
        3C 04             cmp al, 4          ; check if counter equals 4
        75 04             jne being_debugged ; if not, debugger swallowed exceptions
        31 C0             xor eax, eax       ; mov eax, FALSE (0)
        EB 05             jmp end            ; jump over being_debugged
    being_debugged:
        B8 01 00 00 00    mov eax, 1         ; mov eax, TRUE (1)
    end:
        C3                ret
    */
    const uint8_t shellcode[] = {
        0x48, 0x31, 0xC0,
        0x90,
        0x90,
        0x90,
        0x90,
        0x3C, 0x04,
        0x75, 0x04,
        0x31, 0xC0,
        0xEB, 0x05,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };

    PVOID base_address = NULL;
    SIZE_T region_size = 4096;

    PVOID veh = NULL;
    HANDLE thread_handle = NULL;
    bool debugged = false;
    ULONG old_protection = 0;
    SIZE_T free_size = 0;
    NTSTATUS status = 0;

    DbgNtAllocateVirtualMemory(process_handle, &base_address, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base_address)
        goto cleanup;

    memcpy(base_address, shellcode, sizeof(shellcode));

    DbgNtProtectVirtualMemory(process_handle, &base_address, &region_size, PAGE_EXECUTE_READ, &old_protection);

    DbgNtFlushInstructionCache(process_handle, base_address, (ULONG)region_size);

    veh = AddVectoredExceptionHandler(1, _inst_count_excp_handler);
    if (!veh)
        goto cleanup;

    // no need to check for JMP stubs because this is dynamically allocated raw memory
    // 0x1 corresponds to THREAD_CREATE_FLAGS_CREATE_SUSPENDED
    status = DbgNtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS, NULL, process_handle, base_address, NULL, 0x1, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status) || !thread_handle)
        goto cleanup;

    // setup DR0 - DR3
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (NT_SUCCESS(DbgNtGetContextThread(thread_handle, &ctx)))
    {
        // set addresses of the 4 NOPs in our shellcode (offsets 3, 4, 5, 6)
        ctx.Dr0 = (DWORD64)(base_address)+3;
        ctx.Dr1 = (DWORD64)(base_address)+4;
        ctx.Dr2 = (DWORD64)(base_address)+5;
        ctx.Dr3 = (DWORD64)(base_address)+6;

        // DR7 = 0x55 (01010101b) enables execution BPs locally for DR0, DR1, DR2, DR3
        ctx.Dr7 = 0x55;

        DbgNtSetContextThread(thread_handle, &ctx);
    }

    ULONG suspend_count;
    DbgNtResumeThread(thread_handle, &suspend_count);

    DbgNtWaitForSingleObject(thread_handle, FALSE, NULL);

    status = DbgNtQueryInformationThread(thread_handle, 0, &tbi, sizeof(tbi), NULL);
    if (NT_SUCCESS(status))
    {
        debugged = (tbi.ExitStatus == 1);
    }

cleanup:
    if (thread_handle)
        DbgNtClose(thread_handle);

    if (veh)
        RemoveVectoredExceptionHandler(veh);

    if (base_address)
    {
        free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &base_address, &free_size, MEM_RELEASE);
    }

    return debugged;
}