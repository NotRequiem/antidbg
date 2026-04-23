#include <Windows.h>
#include <intrin.h>
#include <immintrin.h>

// manual RtlCaptureContext to avoid user-mode hooks, just in case I need it (somehow) in the future

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline)) void CaptureContextManual(PCONTEXT ctx)
{
    volatile unsigned char probe = 0;

    __asm__ __volatile__(
        "movq %%rax, %0\n\t"
        "movq %%rcx, %1\n\t"
        "movq %%rdx, %2\n\t"
        "movq %%rbx, %3\n\t"
        "movq %%rbp, %4\n\t"
        "movq %%rsi, %5\n\t"
        "movq %%rdi, %6\n\t"
        "movq %%r8,  %7\n\t"
        "movq %%r9,  %8\n\t"
        "movq %%r10, %9\n\t"
        "movq %%r11, %10\n\t"
        "movq %%r12, %11\n\t"
        "movq %%r13, %12\n\t"
        "movq %%r14, %13\n\t"
        "movq %%r15, %14\n\t"
        : "=m"(ctx->Rax), "=m"(ctx->Rcx), "=m"(ctx->Rdx), "=m"(ctx->Rbx),
        "=m"(ctx->Rbp), "=m"(ctx->Rsi), "=m"(ctx->Rdi), "=m"(ctx->R8),
        "=m"(ctx->R9), "=m"(ctx->R10), "=m"(ctx->R11), "=m"(ctx->R12),
        "=m"(ctx->R13), "=m"(ctx->R14), "=m"(ctx->R15)
        :
        : "memory"
    );

    unsigned short cs, ds, es, ss, fs, gs;
    __asm__ __volatile__(
        "movw %%cs, %0\n\t"
        "movw %%ds, %1\n\t"
        "movw %%es, %2\n\t"
        "movw %%ss, %3\n\t"
        "movw %%fs, %4\n\t"
        "movw %%gs, %5\n\t"
        : "=r"(cs), "=r"(ds), "=r"(es), "=r"(ss), "=r"(fs), "=r"(gs)
        :
        : "memory"
    );
    ctx->SegCs = cs;
    ctx->SegDs = ds;
    ctx->SegEs = es;
    ctx->SegSs = ss;
    ctx->SegFs = fs;
    ctx->SegGs = gs;

    unsigned long long eflags = 0;
    __asm__ __volatile__(
        "pushfq\n\t"
        "popq %0\n\t"
        : "=r"(eflags)
        :
        : "memory"
    );
    ctx->EFlags = (DWORD)eflags;

    ctx->Rsp = (DWORD64)&probe;
    ctx->Rip = (DWORD64)__builtin_return_address(0);

    ctx->MxCsr = _mm_getcsr();
    _fxsave((void*)&ctx->FltSave);

    ctx->ContextFlags = CONTEXT_ALL;
}
#else 
__declspec(noinline) void CaptureContextManual(PCONTEXT ctx)
RtlCaptureContext(&ctx);
}
#endif