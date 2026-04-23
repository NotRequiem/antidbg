#include "dbgactproc.h"
#include "..\core\syscall.h"

typedef struct _RTL_USER_PROCESS_PARAMETERS_I {
    uint8_t Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS_I, * PRTL_USER_PROCESS_PARAMETERS_I;

typedef struct _PEB_INTERNAL {
    uint8_t Reserved1[2];
    uint8_t BeingDebugged;
    uint8_t Reserved2[1];
    PVOID Reserved3[2];
    struct _PEB_LDR_DATA* Ldr;
    PRTL_USER_PROCESS_PARAMETERS_I ProcessParameters;
} PEB_INTERNAL, * PPEB_INTERNAL;

typedef struct _DBGUI_WAIT_STATE_CHANGE {
    ULONG NewState;
    CLIENT_ID AppClientId;
    union {
        struct {
            HANDLE HandleToThread;
            HANDLE HandleToProcess;
            CLIENT_ID ClientId;
        } CreateThread;
        struct {
            HANDLE HandleToFile;
            HANDLE HandleToProcess;
            HANDLE HandleToThread;
            PVOID BaseOfImage;
            ULONG DebugInfoFileOffset;
            ULONG DebugInfoSize;
            PVOID ThreadLocalBase;
            PVOID StartAddress;
            PVOID ImageName;
            USHORT ImageNameLength;
            USHORT Unicode;
        } CreateProcessInfo;
        struct {
            ULONG ExceptionCode;
            ULONG FirstChance;
        } Exception;
        // padding for remaining union size, must encapsulate the 64 bit exception record, 256 is normally safe but we put 512 just in case
        uint8_t Padding[512];
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, * PDBGUI_WAIT_STATE_CHANGE;

static inline void close_nt_handle(HANDLE* h)
{
    if (h && *h)
    {
        DbgNtClose(*h);
        *h = NULL;
    }
}

bool __adbg_child_debug_event()
{
    bool result = false;
    HANDLE debug_object = NULL;
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    DBGUI_WAIT_STATE_CHANGE state_change = { 0 };

    si.cb = sizeof(si);

    PPEB_INTERNAL p_peb = (PPEB_INTERNAL)__readgsqword(0x60);
    PWSTR sz_path = p_peb->ProcessParameters->ImagePathName.Buffer;

    // CREATE_NO_WINDOW prevents the suspended child from attaching to the parent's console, 
    // which prevents __log() in the parent thread from deadlocking
    if (!CreateProcessW(sz_path, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi))
    {
        return false;
    }

    OBJECT_ATTRIBUTES object_attributes = { sizeof(OBJECT_ATTRIBUTES), NULL, NULL, 0, NULL, NULL };

    if (!NT_SUCCESS(DbgNtCreateDebugObject(&debug_object, DEBUG_ALL_ACCESS, &object_attributes, 0)))
        goto cleanup;

    if (!NT_SUCCESS(DbgNtDebugActiveProcess(pi.hProcess, debug_object)))
        goto cleanup;

    LARGE_INTEGER timeout = { 0 };
    timeout.QuadPart = -10000000LL;

    NTSTATUS wait_status = DbgNtWaitForDebugEvent(debug_object, TRUE, &timeout, &state_change);

    // NT_SUCCESS considers STATUS_TIMEOUT (0x102) as successful, we must explicitly ensure we actually received a debug event.
    if (NT_SUCCESS(wait_status) && wait_status != 0x00000102L)
    {
        // must satisfy the debug port first
        DbgNtDebugContinue(debug_object, &state_change.AppClientId, DBG_CONTINUE);

        /*
            since this was a CREATE_PROCESS / CREATE_THREAD event, the event payload
            commonly contains handles that belong to the debugger and must be closed
            explicitly, I will let one handle leak 
        */

        // terminate the process WHILE the debug port is still attached to prevent kernel deadlocks
        DbgNtTerminateProcess(pi.hProcess, 0);

        // a suspended thread will not process the termination APC queued by NtTerminateProcess
        // we must resume the thread so it catches the APC and cleanly terminates, 
        // otherwise it becomes a zombie process and leaks handles/locks
        DbgNtResumeThread(pi.hThread, NULL);

        result = false;
        goto cleanup;
    }

    DbgNtTerminateProcess(pi.hProcess, 0);

    // to ensure the termination APC runs
    DbgNtResumeThread(pi.hThread, NULL);

    result = true;

cleanup:
    close_nt_handle(&debug_object);
    close_nt_handle(&pi.hThread);
    close_nt_handle(&pi.hProcess);
    return result;
}