#include "syscall.h"

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

Dbg_SYSCALL_LIST Dbg_SyscallList;

DWORD Dbg_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = Dbg_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + Dbg_ROR8(Hash);
    }

    return Hash;
}

static PVOID SC_Address(PVOID NtApiAddress)
{
    (NtApiAddress);
    return NULL;
}

BOOL Dbg_PopulateSyscallList()
{
    if (Dbg_SyscallList.Count) return TRUE;

    PDbg_PEB Peb = (PDbg_PEB)__readgsqword(0x60);

    PDbg_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    PDbg_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PDbg_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PDbg_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = Dbg_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)Dbg_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        PCHAR DllName = Dbg_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = Dbg_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = Dbg_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = Dbg_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    DWORD i = 0;
    PDbg_SYSCALL_ENTRY Entries = Dbg_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = Dbg_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = Dbg_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(Dbg_RVA2VA(PVOID, DllBase, Entries[i].Address));

            i++;
            if (i == Dbg_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    Dbg_SyscallList.Count = i;

    for (i = 0; i < Dbg_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < Dbg_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                Dbg_SYSCALL_ENTRY TempEntry = { 0 };

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD Dbg_GetSyscallNumber(DWORD FunctionHash)
{
    if (!Dbg_PopulateSyscallList()) return 1;

    for (DWORD i = 0; i < Dbg_SyscallList.Count; i++)
    {
        if (FunctionHash == Dbg_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return 1;
}

EXTERN_C PVOID Dbg_GetSyscallAddress(DWORD FunctionHash)
{
    if (!Dbg_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < Dbg_SyscallList.Count; i++)
    {
        if (FunctionHash == Dbg_SyscallList.Entries[i].Hash)
        {
            return Dbg_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}

EXTERN_C PVOID Dbg_GetRandomSyscallAddress(DWORD FunctionHash)
{
    if (!Dbg_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD)rand()) % Dbg_SyscallList.Count;

    while (FunctionHash == Dbg_SyscallList.Entries[index].Hash) {
        index = ((DWORD)rand()) % Dbg_SyscallList.Count;
    }
    return Dbg_SyscallList.Entries[index].SyscallAddress;
}
