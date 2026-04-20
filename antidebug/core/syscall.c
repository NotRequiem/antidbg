#include "syscall.h"

Dbg_SYSCALL_LIST Dbg_SyscallList;

DWORD __hash_syscall(PCSTR FunctionName)
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

static PVOID _sc_address(PVOID NtApiAddress)
{
    (NtApiAddress);
    return NULL;
}

bool _populate_syscall_list()
{
    if (Dbg_SyscallList.Count) return TRUE;

    pdbg_peb peb = __readpeb();

    PDbg_PEB_LDR_DATA ldr = peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY export_directory = NULL;
    PVOID dll_base = NULL;

    PDbg_LDR_DATA_TABLE_ENTRY ldr_entry;
    for (ldr_entry = (PDbg_LDR_DATA_TABLE_ENTRY)ldr->Reserved2[1]; ldr_entry->DllBase != NULL; ldr_entry = (PDbg_LDR_DATA_TABLE_ENTRY)ldr_entry->Reserved1[0])
    {
        dll_base = ldr_entry->DllBase;
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_base;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) continue;

        PIMAGE_NT_HEADERS nt_headers = __rva2va(PIMAGE_NT_HEADERS, dll_base, dos_header->e_lfanew);
        PIMAGE_DATA_DIRECTORY data_directory = (PIMAGE_DATA_DIRECTORY)nt_headers->OptionalHeader.DataDirectory;
        DWORD virtual_address = data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (virtual_address == 0) continue;

        export_directory = (PIMAGE_EXPORT_DIRECTORY)__rva2va(ULONG_PTR, dll_base, virtual_address);
        PCHAR dll_name = __rva2va(PCHAR, dll_base, export_directory->Name);

        if ((*(ULONG*)dll_name | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(dll_name + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!export_directory) return false;

    DWORD number_of_names = export_directory->NumberOfNames;
    PDWORD functions = __rva2va(PDWORD, dll_base, export_directory->AddressOfFunctions);
    PDWORD names = __rva2va(PDWORD, dll_base, export_directory->AddressOfNames);
    PWORD ordinals = __rva2va(PWORD, dll_base, export_directory->AddressOfNameOrdinals);

    DWORD i = 0;
    PDbg_SYSCALL_ENTRY entries = Dbg_SyscallList.Entries;
    do
    {
        PCHAR function_name = __rva2va(PCHAR, dll_base, names[number_of_names - 1]);

        if (*(USHORT*)function_name == 0x775a) // "Zw"
        {
            entries[i].Hash = __hash_syscall(function_name);
            entries[i].Address = functions[ordinals[number_of_names - 1]];
            entries[i].SyscallAddress = _sc_address(__rva2va(PVOID, dll_base, entries[i].Address));

            i++;
            if (i == Dbg_MAX_ENTRIES) break;
        }
    } while (--number_of_names);

    Dbg_SyscallList.Count = i;

    // sSort by RVA to automatically align the syscall numbers
    for (i = 0; i < Dbg_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < Dbg_SyscallList.Count - i - 1; j++)
        {
            if (entries[j].Address > entries[j + 1].Address)
            {
                Dbg_SYSCALL_ENTRY temp_entry = entries[j];
                entries[j] = entries[j + 1];
                entries[j + 1] = temp_entry;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD __adbg_syscall(DWORD function_hash)
{
    if (!_populate_syscall_list()) return 1;
    for (DWORD i = 0; i < Dbg_SyscallList.Count; i++)
    {
        if (function_hash == Dbg_SyscallList.Entries[i].Hash)
        {
            return i; // the index is the SSN
        }
    }
    return 1;
}