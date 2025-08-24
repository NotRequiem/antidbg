#include "hwbreakp2.h"
#include "..\core\syscall.h"

bool HardwareBreakPoint2(const HANDLE hThread, const HANDLE hProcess)
{
    bool bResult = FALSE;
    PVOID BaseAddress = NULL;
    SIZE_T RegionSize = sizeof(CONTEXT);
    ULONG AllocationType = MEM_COMMIT;
    ULONG Protect = PAGE_READWRITE;

    const NTSTATUS status = DbgNtAllocateVirtualMemory(
        hProcess,
        &BaseAddress,
        0,
        &RegionSize,
        AllocationType,
        Protect
    );

    if (((NTSTATUS)(status) >= 0)) {
        PCONTEXT ctx = (PCONTEXT)BaseAddress;

        SecureZeroMemory(ctx, sizeof(CONTEXT));

        ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (DbgNtGetContextThread(hThread, ctx)) {
            if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
                bResult = TRUE;
        }

        SIZE_T freeSize = 0;
        DbgNtFreeVirtualMemory(hProcess, (PVOID*)&ctx, &freeSize, MEM_RELEASE);
    }

    return bResult;
}
