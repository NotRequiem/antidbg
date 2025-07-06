#include "atcptr.h"

void __stdcall AntiAttach(void)
{
    ExitProcess(0);
    __fastfail(0);
}

bool StartAttachProtection(const HANDLE hProcess)
{
    DWORD oldProtect = 0;

    char* baseAdress = (char*)GetModuleHandle(NULL);

    VirtualProtect(baseAdress, 4096,
        PAGE_READWRITE, &oldProtect);

    ZeroMemory(baseAdress, 4096);

    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (!hNtdll) {
        return false;
    }

    void* target = (void*)GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
    if (!target) {
        return false;
    }

    // build the 5-byte relative JMP (E9 xx xx xx xx) + 1-byte NOP padding
    unsigned char patch[6] = { 0 };

    // calculate rel32: destination - (source + 5), source is the address we’re patching; +5 because E9+4-byte offset
    uintptr_t src = (uintptr_t)target;
    uintptr_t dst = (uintptr_t)&AntiAttach;
    int rel = (int)(dst - (src + 5));

    patch[0] = 0xE9;                       // JMP rel32 opcode
    memcpy(patch + 1, &rel, sizeof(rel));  // rel32 little-endian
    patch[5] = 0x90;                       // one NOP to make it 6 bytes total

    if (!VirtualProtect(target, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    // overwrite the first 6 bytes with our JMP
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, target, patch, sizeof(patch), &bytesWritten)
        || bytesWritten != sizeof(patch)) {
        return false;
    }

    return true;
}
