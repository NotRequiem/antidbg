#pragma once

#pragma warning (disable: 4201)

#include "nttypes.h" 

#define Dbg_SEED 0x28C5192F
#define Dbg_ROL8(v) (v << 8 | v >> 24)
#define Dbg_ROR8(v) (v >> 8 | v << 24)
#define Dbg_ROX8(v) ((Dbg_SEED % 2) ? Dbg_ROL8(v) : Dbg_ROR8(v))
#define Dbg_MAX_ENTRIES 600
#define __rva2va(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

typedef struct _Dbg_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
} Dbg_SYSCALL_ENTRY, * PDbg_SYSCALL_ENTRY;

typedef struct _Dbg_SYSCALL_LIST
{
    DWORD Count;
    Dbg_SYSCALL_ENTRY Entries[Dbg_MAX_ENTRIES];
} Dbg_SYSCALL_LIST, * PDbg_SYSCALL_LIST;

#ifndef EXTERN_C
    #ifdef __cplusplus
        #define EXTERN_C extern "C"
    #else
        #define EXTERN_C extern
    #endif
#endif

#define SYSCALL_DEFINE(name, retType, ...) \
    EXTERN_C retType DbgNt##name(__VA_ARGS__);

#ifndef UNREFERENCED_PARAMETER
    #define UNREFERENCED_PARAMETER(x) (void)(x)
#endif

    #ifdef _MSC_VER
    #include <intrin.h>
    static inline pdbg_peb __readpeb(void) {
        return (pdbg_peb)__readgsqword(0x60);
    }

#else
    static inline pdbg_peb __readpeb(void) {
        pdbg_peb peb;
        __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
        return peb;
    }

#endif

EXTERN_C DWORD __adbg_syscall(DWORD FunctionHash);
DWORD __hash_syscall(PCSTR FunctionName);
bool _populate_syscall_list();

#include "syscalls.h"