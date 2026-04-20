#include "movss.h"

#if defined(_MSC_VER) && !defined(__clang__)

    #pragma section(".__stub", execute, read)

    __declspec(allocate(".__stub")) const uint8_t _movss_stub[] = {
        0x66, 0x8C, 0xD0, 0x66, 0x8E, 0xD0, 0x9C, 0x58, 0x48, 0xC1, 0xE8, 0x08, 0x48, 0x83, 0xE0, 0x01, 0xC3
    }; // mov ax, ss; mov ss, ax; pushfq; pop rax; shr rax, 8; and rax, 1; ret

    bool __adbg_mov_ss()
    {
        typedef bool(*_movss_func)();
        return ((_movss_func)_movss_stub)();
    }

#else 

    bool __adbg_mov_ss()
    {
        uint64_t rflags = 0;
        __asm__ __volatile__(
            "mov %%ss, %%ax \n\t"
            "mov %%ax, %%ss \n\t"
            "pushfq \n\t"
            "pop %0 \n\t"
            : "=r" (rflags)
            :
            : "rax"
        );
        return (rflags & 0x100) != 0;
    }

#endif