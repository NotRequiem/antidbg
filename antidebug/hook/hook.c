// Still in progress

#include <Windows.h>
#include <stdio.h>
#include "MinHook.h"

#pragma comment(lib, "libMinHook.x64.lib")

typedef HMODULE(WINAPI* PLoadLibraryA)(LPCSTR lpLibFileName);
typedef HMODULE(WINAPI* PLoadLibraryW)(LPCWSTR lpLibFileName);
typedef BOOL(WINAPI* PWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* PCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef LPVOID(WINAPI* PVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HHOOK(WINAPI* PSetWindowsHookExA)(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
typedef HHOOK(WINAPI* PSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
typedef LPVOID(WINAPI* PHeapCreate)(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
typedef HANDLE(WINAPI* POpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

PLoadLibraryA TrueLoadLibraryA = NULL;
PLoadLibraryW TrueLoadLibraryW = NULL;
PWriteProcessMemory TrueWriteProcessMemory = NULL;
PCreateRemoteThread TrueCreateRemoteThread = NULL;
PVirtualAllocEx TrueVirtualAllocEx = NULL;
PSetWindowsHookExA TrueSetWindowsHookExA = NULL;
PSetWindowsHookExW TrueSetWindowsHookExW = NULL;
PHeapCreate TrueHeapCreate = NULL;
POpenProcess TrueOpenProcess = NULL;

static BOOL IsCallingProcessValid() {
    HANDLE hCurrentProcess = GetCurrentProcess();
    HANDLE hCallingProcess;
    GetWindowThreadProcessId(GetForegroundWindow(), (LPDWORD)&hCallingProcess);
    return hCallingProcess == hCurrentProcess;
}

static HMODULE WINAPI ProtectedLoadLibraryA(LPCSTR lpLibFileName) {
    if (IsCallingProcessValid()) {
        return TrueLoadLibraryA(lpLibFileName);
    }
    else {
        printf("Blocked LoadLibraryA attempt!\n");
        return NULL;
    }
}

static HMODULE WINAPI ProtectedLoadLibraryW(LPCWSTR lpLibFileName) {
    if (IsCallingProcessValid()) {
        return TrueLoadLibraryW(lpLibFileName);
    }
    else {
        printf("Blocked LoadLibraryW attempt!\n");
        return NULL;
    }
}

static BOOL WINAPI ProtectedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    if (IsCallingProcessValid()) {
        return TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
    else {
        printf("Blocked WriteProcessMemory attempt!\n");
        return FALSE;
    }
}

static HANDLE WINAPI ProtectedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    if (IsCallingProcessValid()) {
        return TrueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    else {
        printf("Blocked CreateRemoteThread attempt!\n");
        return NULL;
    }
}

static LPVOID WINAPI ProtectedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (IsCallingProcessValid()) {
        return TrueVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    }
    else {
        printf("Blocked VirtualAllocEx attempt!\n");
        return NULL;
    }
}

static HHOOK WINAPI ProtectedSetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {
    if (IsCallingProcessValid()) {
        return TrueSetWindowsHookExA(idHook, lpfn, hMod, dwThreadId);
    }
    else {
        printf("Blocked SetWindowsHookExA attempt!\n");
        return NULL;
    }
}

static HHOOK WINAPI ProtectedSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId) {
    if (IsCallingProcessValid()) {
        return TrueSetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
    }
    else {
        printf("Blocked SetWindowsHookExW attempt!\n");
        return NULL;
    }
}

static LPVOID WINAPI ProtectedHeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    if (IsCallingProcessValid()) {
        return TrueHeapCreate(flOptions, dwInitialSize, dwMaximumSize);
    }
    else {
        printf("Blocked HeapCreate attempt!\n");
        return NULL;
    }
}

static HANDLE WINAPI ProtectedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    if (IsCallingProcessValid()) {
        return TrueOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }
    else {
        printf("Blocked OpenProcess attempt!\n");
        return NULL;
    }
}

int main() {
    if (MH_Initialize() != MH_OK) {
        printf("MH_Initialize failed!\n");
        return 1;
    }

    TrueLoadLibraryA = &LoadLibraryA;
    TrueLoadLibraryW = &LoadLibraryW;
    TrueWriteProcessMemory = &WriteProcessMemory;
    TrueCreateRemoteThread = &CreateRemoteThread;
    TrueVirtualAllocEx = &VirtualAllocEx;
    TrueSetWindowsHookExA = &SetWindowsHookExA;
    TrueSetWindowsHookExW = &SetWindowsHookExW;
    TrueHeapCreate = &HeapCreate;
    TrueOpenProcess = &OpenProcess;

    struct {
        void** hookFunction;
        void* ProtectedFunction;
        void* trueFunction;
    } hooks[] = {
        { (void**)&LoadLibraryA, (void*)(&ProtectedLoadLibraryA), (void*)(&TrueLoadLibraryA) },
        { (void**)&LoadLibraryW, (void*)(&ProtectedLoadLibraryW), (void*)(&TrueLoadLibraryW) },
        { (void**)&WriteProcessMemory, (void*)(&ProtectedWriteProcessMemory), (void*)(&TrueWriteProcessMemory) },
        { (void**)&CreateRemoteThread, (void*)(&ProtectedCreateRemoteThread), (void*)(&TrueCreateRemoteThread) },
        { (void**)&VirtualAllocEx, (void*)(&ProtectedVirtualAllocEx), (void*)(&TrueVirtualAllocEx) },
        { (void**)&SetWindowsHookExA, (void*)(&ProtectedSetWindowsHookExA), (void*)(&TrueSetWindowsHookExA) },
        { (void**)&SetWindowsHookExW, (void*)(&ProtectedSetWindowsHookExW), (void*)(&TrueSetWindowsHookExW) },
        { (void**)&HeapCreate, (void*)(&ProtectedHeapCreate), (void*)(&TrueHeapCreate) },
        { (void**)&OpenProcess, (void*)(&ProtectedOpenProcess), (void*)(&TrueOpenProcess) },
    };

    int numHooks = sizeof(hooks) / sizeof(hooks[0]);
    int success = 1;

    for (int i = 0; i < numHooks; ++i) {
        if (MH_CreateHook(hooks[i].hookFunction, hooks[i].ProtectedFunction, (PVOID*)&hooks[i].trueFunction) != MH_OK) {
            printf("MH_CreateHook failed for hook %d!\n", i);
            success = 0;
        }

        if (MH_EnableHook(hooks[i].hookFunction) != MH_OK) {
            printf("MH_EnableHook failed for hook %d!\n", i);
            success = 0;
        }
    }

    if (!success) {
        printf("One or more hooks failed to create or enable!\n");
    }

    for (int i = 0; i < numHooks; ++i) {
        if (MH_DisableHook(hooks[i].hookFunction) != MH_OK) {
            printf("MH_DisableHook failed for hook %d!\n", i);
            success = 0;
        }
    }

    if (MH_Uninitialize() != MH_OK) {
        printf("MH_Uninitialize failed!\n");
        success = 0;
    }

    if (!success) {
        printf("Failed to disable, uninitialize hooks, or execute main code!\n");
    }

    return 0;
}
