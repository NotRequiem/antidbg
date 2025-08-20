#pragma once

#pragma warning (disable: 4201)

#include "nttypes.h" 

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif

#define Dbg_SEED 0x28C5192F
#define Dbg_ROL8(v) (v << 8 | v >> 24)
#define Dbg_ROR8(v) (v >> 8 | v << 24)
#define Dbg_ROX8(v) ((Dbg_SEED % 2) ? Dbg_ROL8(v) : Dbg_ROR8(v))
#define Dbg_MAX_ENTRIES 600
#define Dbg_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

typedef struct _Dbg_SYSCALL_ENTRY
{
	DWORD Hash;
	DWORD Address; // RVA of the function
	PVOID SyscallAddress; // Pointer to the syscall stub (for GCC/Clang)
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

DWORD Dbg_HashSyscall(PCSTR FunctionName);
BOOL Dbg_PopulateSyscallList();
EXTERN_C PVOID Dbg_GetSyscallAddress(DWORD FunctionHash);

#ifdef _MSC_VER
    #define SYSCALL_DEFINE(name, retType, ...) \
        EXTERN_C retType DbgNt##name(__VA_ARGS__);
#else
    #define SYSCALL_HASH_NAME(name) "Zw" #name

    #define SYSCALL_DEFINE(name, retType, ...) \
        EXTERN_C retType DbgNt##name(__VA_ARGS__) { \
            PVOID pfnSyscall = Dbg_GetSyscallAddress(Dbg_HashSyscall(SYSCALL_HASH_NAME(name))); \
            if (!pfnSyscall) { \
                return (retType)STATUS_UNSUCCESSFUL; \
            } \
            typedef retType (NTAPI *t_##name)(__VA_ARGS__); \
            return ((t_##name)pfnSyscall)(__VA_ARGS__); \
        }
#endif

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) (void)(x)
#endif

#ifdef _MSC_VER
#include <intrin.h>
static inline PDbg_PEB ReadPEB(void) {
    return (PDbg_PEB)__readgsqword(0x60);
}
#else
static inline PDbg_PEB ReadPEB(void) {
    PDbg_PEB peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}
#endif

#include "syscalls.h"