#include "syscall.h"

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

#ifdef _MSC_VER
static PVOID SC_Address(PVOID NtApiAddress)
{
    (NtApiAddress);
    return NULL;
}

BOOL Dbg_PopulateSyscallList()
{
    if (Dbg_SyscallList.Count) return TRUE;

    PDbg_PEB Peb = ReadPEB();

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
    UNREFERENCED_PARAMETER(FunctionHash);
    return NULL;
}

#else
// mov r10, rcx; mov eax, <SSN>; syscall; ret
static const BYTE SyscallStub[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
static PVOID g_pStubs = NULL;

BOOL Dbg_PopulateSyscallList()
{
    if (Dbg_SyscallList.Count) return TRUE;

    // Allocate executable memory for all the stubs at once
    g_pStubs = VirtualAlloc(NULL, sizeof(SyscallStub) * Dbg_MAX_ENTRIES, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_pStubs)
    {
        return FALSE;
    }

    PDbg_PEB Peb = ReadPEB();
    PDbg_PEB_LDR_DATA Ldr = Peb->Ldr;
    PVOID DllBase = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;

    // find ntdll.dll
    PDbg_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PDbg_LDR_DATA_TABLE_ENTRY)Ldr->InMemoryOrderModuleList.Flink; LdrEntry->DllBase != NULL; LdrEntry = (PDbg_LDR_DATA_TABLE_ENTRY)LdrEntry->InMemoryOrderLinks.Flink)
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) continue;
        PIMAGE_NT_HEADERS NtHeaders = Dbg_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) continue;

        DWORD VirtualAddress = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)Dbg_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
        PCHAR DllName = Dbg_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) == 0x6c64746e && (*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c)
        {
            break; // Found ntdll.dll
        }
    }

    if (!ExportDirectory) return FALSE;

    // The rest is similar to the MSVC version, but we populate the stubs
    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = Dbg_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = Dbg_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = Dbg_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    DWORD i = 0;
    PDbg_SYSCALL_ENTRY Entries = Dbg_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = Dbg_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);
        if (*(USHORT*)FunctionName == 0x775a) // "Zw"
        {
            Entries[i].Hash = Dbg_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            i++;
            if (i == Dbg_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    Dbg_SyscallList.Count = i;

    // Sort by RVA to get the correct SSN order
    for (i = 0; i < Dbg_SyscallList.Count - 1; i++) {
        for (DWORD j = 0; j < Dbg_SyscallList.Count - i - 1; j++) {
            if (Entries[j].Address > Entries[j + 1].Address) {
                Dbg_SYSCALL_ENTRY TempEntry = Entries[j];
                Entries[j] = Entries[j + 1];
                Entries[j + 1] = TempEntry;
            }
        }
    }

    // Generate stubs with the correct SSNs (the SSN is the index 'i')
    for (i = 0; i < Dbg_SyscallList.Count; i++)
    {
        PBYTE pStub = (PBYTE)g_pStubs + (i * sizeof(SyscallStub));
        memcpy(pStub, SyscallStub, sizeof(SyscallStub));
        *(DWORD*)(pStub + 4) = i; 
        Entries[i].SyscallAddress = pStub;
    }

    return TRUE;
}

EXTERN_C PVOID Dbg_GetSyscallAddress(DWORD FunctionHash)
{
    if (!Dbg_SyscallList.Count)
    {
        if (!Dbg_PopulateSyscallList())
        {
            return NULL;
        }
    }
    for (DWORD i = 0; i < Dbg_SyscallList.Count; i++)
    {
        if (FunctionHash == Dbg_SyscallList.Entries[i].Hash)
        {
            return Dbg_SyscallList.Entries[i].SyscallAddress;
        }
    }
    return NULL;
}

#endif // _MSC_VER

EXTERN_C PVOID Dbg_GetRandomSyscallAddress(DWORD FunctionHash)
{
    if (!Dbg_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD)rand()) % Dbg_SyscallList.Count;

    while (FunctionHash == Dbg_SyscallList.Entries[index].Hash) {
        index = ((DWORD)rand()) % Dbg_SyscallList.Count;
    }
    return Dbg_SyscallList.Entries[index].SyscallAddress;
}