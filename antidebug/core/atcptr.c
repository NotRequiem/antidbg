#include "atcptr.h"
#include "syscall.h"

static void __stdcall AntiAttach(void);
void __stdcall clb(PVOID DllHandle, DWORD reason, PVOID Reserved);

// some virtualizers can't obfuscate TLS callbacks. If this is a problem for you, just remove this code block 
#pragma region TLS_CALLBACK_SETUP
#ifdef _WIN64
    #pragma comment (linker, "/INCLUDE:_tls_used")
    #pragma const_seg(".CRT$XLA")
    EXTERN_C const PIMAGE_TLS_CALLBACK p_thread_callback_list[] = { (PIMAGE_TLS_CALLBACK)clb, NULL };
    #pragma const_seg()
#else
    #pragma comment (linker, "/INCLUDE:__tls_used")
    #pragma data_seg(".CRT$XLA")
    EXTERN_C PIMAGE_TLS_CALLBACK p_thread_callback_list[] = { (PIMAGE_TLS_CALLBACK)clb, NULL };
    #pragma data_seg()
#endif
#pragma endregion

void __stdcall clb(PVOID DllHandle, DWORD reason, PVOID Reserved)
{
    UNREFERENCED_PARAMETER(DllHandle);
    UNREFERENCED_PARAMETER(Reserved);

    if (reason != DLL_THREAD_ATTACH)
    {
        return;
    }
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (!hNtdll) return;

    const FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
    if (!pDbgUiRemoteBreakin) return;

    ULONG cbBuffer = 0x8000;
    PVOID pBuffer = NULL;
    NTSTATUS status;

    do {
        pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer);
        if (!pBuffer) return;

        status = DbgNtQuerySystemInformation(SystemProcessInformation, pBuffer, cbBuffer, NULL);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(GetProcessHeap(), 0, pBuffer);
            cbBuffer *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        if (pBuffer) HeapFree(GetProcessHeap(), 0, pBuffer);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION pCurrentProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    const DWORD currentProcessId = GetCurrentProcessId();
    const DWORD currentThreadId = GetCurrentThreadId();

    while (TRUE)
    {
        if ((ULONG_PTR)pCurrentProcInfo->UniqueProcessId == (ULONG_PTR)currentProcessId)
        {
            PSYSTEM_THREAD_INFORMATION pThreadInfo = (PSYSTEM_THREAD_INFORMATION)(pCurrentProcInfo + 1);

            for (unsigned int i = 0; i < pCurrentProcInfo->NumberOfThreads; i++)
            {
                if ((ULONG_PTR)pThreadInfo[i].ClientId.UniqueThread == (ULONG_PTR)currentThreadId)
                {
                    if (pThreadInfo[i].StartAddress == pDbgUiRemoteBreakin)
                    {
                        __fastfail(STATUS_ACCESS_VIOLATION);
                    }
                    break;
                }
            }
            break;
        }

        if (pCurrentProcInfo->NextEntryOffset == 0) break;
        pCurrentProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrentProcInfo + pCurrentProcInfo->NextEntryOffset);
    }

    if (pBuffer) HeapFree(GetProcessHeap(), 0, pBuffer);
}

static void __stdcall AntiAttach(void)
{
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

// not directly syscalled because we don't really care too much, we will be checking debug registers at random times during all the program's lifecycle with direct kernel calls
static void ClearHardwareBreakpoints()
{
    const DWORD currentPid = GetCurrentProcessId();
    const DWORD currentTid = GetCurrentThreadId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = { 0 };
    te.dwSize = sizeof(te);

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == currentPid) {
                if (te.th32ThreadID == currentTid) {
                    continue;
                }

                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (SuspendThread(hThread) != (DWORD)-1) {
                        CONTEXT ctx = { 0 };
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                        if (GetThreadContext(hThread, &ctx)) {
                            ctx.Dr0 = 0;
                            ctx.Dr1 = 0;
                            ctx.Dr2 = 0;
                            ctx.Dr3 = 0;
                            ctx.Dr7 = 0;
                            SetThreadContext(hThread, &ctx);
                        }
                        ResumeThread(hThread);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

bool StartAttachProtection(void)
{
    HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
    if (!hNtdll) return FALSE;

    ClearHardwareBreakpoints();

    void* pDbgUiRemoteBreakin = (void*)GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
    if (pDbgUiRemoteBreakin) {
        DWORD oldProtect;
        if (VirtualProtect(pDbgUiRemoteBreakin, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // absolute just in case the target is >2GB away
            unsigned char patch[12] = { 0 };
            patch[0] = 0x48; // REX.W prefix for 64-bit operand
            patch[1] = 0xB8; // MOV RAX, imm64
            *(ULONGLONG*)&patch[2] = (ULONGLONG)&AntiAttach;
            patch[10] = 0xFF; // JMP RAX
            patch[11] = 0xE0;

            SIZE_T bytesWritten;
            WriteProcessMemory(GetCurrentProcess(), pDbgUiRemoteBreakin, patch, sizeof(patch), &bytesWritten);
            VirtualProtect(pDbgUiRemoteBreakin, 6, oldProtect, &oldProtect);
        }
    }

    void* pDbgBreakPoint = (void*)GetProcAddress(hNtdll, "DbgBreakPoint");
    if (pDbgBreakPoint) {
        DWORD dwOldProtect;
        if (VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            unsigned char patch[] = { 0xC3 }; // ret
            WriteProcessMemory(GetCurrentProcess(), pDbgBreakPoint, patch, sizeof(patch), NULL);
            VirtualProtect(pDbgBreakPoint, 1, dwOldProtect, &dwOldProtect);
        }
    }

    return TRUE;
}