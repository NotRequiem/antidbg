#include "guard.h"
#include "syscall.h"
#include "callback.h"
#include "module.h"

static void __stdcall __anti_attach(void);
void __stdcall __clb(PVOID DllHandle, DWORD reason, PVOID Reserved);

// some virtualizers can't obfuscate TLS callbacks. If this is a problem for you, just remove this code block 
#pragma region TLS_CALLBACK_SETUP
#ifdef _WIN64
    #pragma comment (linker, "/INCLUDE:_tls_used")
    #pragma const_seg(".CRT$XLA")
    const PIMAGE_TLS_CALLBACK p_thread_callback_list[] = { (PIMAGE_TLS_CALLBACK)__clb, NULL };
    #pragma const_seg()
#else
    #pragma comment (linker, "/INCLUDE:__tls_used")
    #pragma data_seg(".CRT$XLA")
    PIMAGE_TLS_CALLBACK p_thread_callback_list[] = { (PIMAGE_TLS_CALLBACK)clb, NULL };
    #pragma data_seg()
#endif
#pragma endregion


static _force_inline DWORD __readprocid()
{
    const PBYTE teb = (PBYTE)__readgsqword(0x30);
    return (DWORD)(*(ULONG_PTR*)(teb + 0x40));
}

static _force_inline DWORD __readthreadid()
{
    const PBYTE teb = (PBYTE)__readgsqword(0x30);
    return (DWORD)(*(ULONG_PTR*)(teb + 0x48));
}


void __stdcall __clb(PVOID DllHandle, DWORD reason, PVOID Reserved)
{
    UNREFERENCED_PARAMETER(DllHandle);
    UNREFERENCED_PARAMETER(Reserved);

    // only run when a new thread is spawned (this intercepts the debugger's remote thread)
    if (reason != DLL_THREAD_ATTACH)
    {
        return;
    }

    const PVOID dbg_ui_remote_breakin = __get_module("ntdll.dll", "DbgUiRemoteBreakin");
    if (!dbg_ui_remote_breakin) return;

    SIZE_T cb_buffer = 0x8000;
    PVOID buffer = NULL;
    NTSTATUS status;
    HANDLE process_handle = (HANDLE)(-1);

    do {
        buffer = NULL;
        status = DbgNtAllocateVirtualMemory(process_handle, &buffer, 0, &cb_buffer, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status < 0 || !buffer) return;

        status = DbgNtQuerySystemInformation(SystemProcessInformation, buffer, (ULONG)cb_buffer, NULL);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            SIZE_T free_size = 0;
            DbgNtFreeVirtualMemory(process_handle, &buffer, &free_size, MEM_RELEASE);
            cb_buffer *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status < 0) {
        if (buffer) {
            SIZE_T free_size = 0;
            DbgNtFreeVirtualMemory(process_handle, &buffer, &free_size, MEM_RELEASE);
        }
        return;
    }

    PSYSTEM_PROCESS_INFORMATION current_process_info = (PSYSTEM_PROCESS_INFORMATION)buffer;
    const DWORD current_process_id = __readprocid();
    const DWORD current_thread_id = __readthreadid();

    while (TRUE)
    {
        if ((ULONG_PTR)current_process_info->UniqueProcessId == (ULONG_PTR)current_process_id)
        {
            PSYSTEM_THREAD_INFORMATION thread_info = (PSYSTEM_THREAD_INFORMATION)((PUCHAR)current_process_info + sizeof(SYSTEM_PROCESS_INFORMATION));

            for (ULONG i = 0; i < current_process_info->NumberOfThreads; i++)
            {
                if ((ULONG_PTR)thread_info[i].ClientId.UniqueThread == (ULONG_PTR)current_thread_id)
                {
                    if (thread_info[i].StartAddress == dbg_ui_remote_breakin)
                    {
                        __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
                    }
                    break;
                }
            }
            break;
        }

        if (current_process_info->NextEntryOffset == 0) break;
        current_process_info = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)current_process_info + current_process_info->NextEntryOffset);
    }

    if (buffer) {
        SIZE_T free_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &buffer, &free_size, MEM_RELEASE);
    }
}

static void __stdcall __anti_attach(void)
{
    __fastfail(STATUS_SXS_EARLY_DEACTIVATION);
}

// not directly syscalled because we don't really care too much, we will be checking debug registers at random times during all the program's lifecycle with direct kernel calls
static void __clear_breakpoints()
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

                HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (thread_handle) {
                    if (SuspendThread(thread_handle) != (DWORD)-1) {
                        CONTEXT ctx = { 0 };
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                        if (GetThreadContext(thread_handle, &ctx)) {
                            ctx.Dr0 = 0;
                            ctx.Dr1 = 0;
                            ctx.Dr2 = 0;
                            ctx.Dr3 = 0;
                            ctx.Dr7 = 0;
                            SetThreadContext(thread_handle, &ctx);
                        }
                        ResumeThread(thread_handle);
                    }
                    DbgNtClose(thread_handle);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    DbgNtClose(hSnap);
}

static inline bool __harden_process(void)
{
    // DEP
    PROCESS_MITIGATION_DEP_POLICY dep = { 0 };
    dep.Enable = 1;
    dep.DisableAtlThunkEmulation = 1;
    dep.Permanent = 1;
    if (!SetProcessMitigationPolicy(ProcessDEPPolicy, &dep, sizeof(dep))) return false;

    // ASLR
    PROCESS_MITIGATION_ASLR_POLICY aslr = { 0 };
    aslr.EnableBottomUpRandomization = 1;
    aslr.EnableForceRelocateImages = 1;
    aslr.EnableHighEntropy = 1;
    aslr.DisallowStrippedImages = 1;
    if (!SetProcessMitigationPolicy(ProcessASLRPolicy, &aslr, sizeof(aslr))) return false;

    // disable legacy extension-point hooks
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext = { 0 };
    ext.DisableExtensionPoints = 1;
    if (!SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ext, sizeof(ext))) return false;

    // no child processes
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY child = { 0 };
    child.NoChildProcessCreation = 1;
    if (!SetProcessMitigationPolicy(ProcessChildProcessPolicy, &child, sizeof(child))) return false;

    // reduce DLL injection / sideloading
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY img = { 0 };
    img.NoRemoteImages = 1;
    img.NoLowMandatoryLabelImages = 1;
    img.PreferSystem32Images = 1;
    if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &img, sizeof(img))) return false;

    // only Microsoft-signed binaries
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig = { 0 };
    sig.MicrosoftSignedOnly = 1;
    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &sig, sizeof(sig))) return false;

    // disable non-system fonts
    PROCESS_MITIGATION_FONT_DISABLE_POLICY font = { 0 };
    font.DisableNonSystemFonts = 1;
    if (!SetProcessMitigationPolicy(ProcessFontDisablePolicy, &font, sizeof(font))) return false;

    // optional
    /*
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY sys = { 0 };
    sys.DisallowWin32kSystemCalls = 1;
    if (!SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &sys, sizeof(sys))) return FALSE;
    */

    // only if your app is CFG-compatible
    /*
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = { 0 };
    cfg.StrictMode = 1;
    if (!SetMitigation(ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg))) return FALSE;
    */

    return true;
}

static inline void __hide_threads(const HANDLE process_handle)
{
    HANDLE thread_handle = NULL;

    while (NT_SUCCESS(DbgNtGetNextThread(
        process_handle,               
        thread_handle,                
        THREAD_SET_INFORMATION, 
        0,                     
        0,                   
        &thread_handle)))            
    {
        DbgNtSetInformationThread(thread_handle, ThreadHideFromDebugger, NULL, 0);
    }
}

static inline bool __clear_ifeo(const HANDLE process_handle)
{
    NTSTATUS status;
    ULONG needed = 0;
    PVOID image_buf = NULL;
    SIZE_T image_size = 0;
    UNICODE_STRING key_name = { 0 };
    UNICODE_STRING parent_name = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };
    HANDLE key_handle = NULL;
    WCHAR* exe_name;
    size_t exe_len = 0;

    status = DbgNtQueryInformationProcess(process_handle, (PROCESSINFOCLASS)ProcessImageFileName, NULL, 0, &needed);
    if (needed == 0)
        return false;

    image_size = (SIZE_T)needed + sizeof(WCHAR);
    status = DbgNtAllocateVirtualMemory(process_handle, &image_buf, 0, &image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status < 0)
        return false;

    status = DbgNtQueryInformationProcess(process_handle, (PROCESSINFOCLASS)ProcessImageFileName, image_buf, needed, &needed);
    if (status < 0)
        goto done;

    exe_name = wcsrchr(((UNICODE_STRING*)image_buf)->Buffer, L'\\');
    exe_name = exe_name == NULL ? ((UNICODE_STRING*)image_buf)->Buffer : exe_name + 1;

    if (StringCchLengthW(exe_name, needed / sizeof(WCHAR), &exe_len) != S_OK)
        goto done;

    parent_name.Buffer = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    parent_name.Length = (USHORT)(wcslen(parent_name.Buffer) * sizeof(WCHAR));
    parent_name.MaximumLength = (USHORT)((wcslen(parent_name.Buffer) + 1) * sizeof(WCHAR));

    key_name.Buffer = exe_name;
    key_name.Length = (USHORT)(exe_len * sizeof(WCHAR));
    key_name.MaximumLength = (USHORT)((exe_len + 1) * sizeof(WCHAR));

    InitializeObjectAttributes(&oa, &parent_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = DbgNtOpenKey(&key_handle, DELETE | KEY_WOW64_64KEY, &oa);
    if (status < 0)
        goto done;

    InitializeObjectAttributes(&oa, &key_name, OBJ_CASE_INSENSITIVE, key_handle, NULL);
    status = DbgNtOpenKey(&key_handle, DELETE | KEY_WOW64_64KEY, &oa);
    if (status < 0)
        goto done;

    status = DbgNtDeleteKey(key_handle);

done:
    if (key_handle != NULL)
        DbgNtClose(key_handle);

    if (image_buf != NULL) {
        image_size = 0;
        DbgNtFreeVirtualMemory(process_handle, &image_buf, &image_size, MEM_RELEASE);  
    }
    return status >= 0;
}

bool __setup_protection(const HANDLE process_handle)
{
    __harden_process();
    __clear_breakpoints();
    __clear_ifeo(process_handle); // not called in TLS callback because we don't care too much
    __hide_threads(process_handle); // redundancy is always good

    if (!__set_callback(&g_callback_page, process_handle))
        __fastfail(STATUS_SXS_EARLY_DEACTIVATION);

    PVOID db_ui_remote_breakin = (PVOID)__get_module("ntdll.dll", "DbgUiRemoteBreakin");
    if (db_ui_remote_breakin)
    {
        ULONG old_protection = 0;
        PVOID base_address = db_ui_remote_breakin;
        SIZE_T region_size = 12;

        // DbgNtProtectVirtualMemory modifies base_address and region_size, so we pass copies
        if (NT_SUCCESS(DbgNtProtectVirtualMemory(process_handle, &base_address, &region_size, PAGE_EXECUTE_READWRITE, &old_protection)))
        {
            // absolute just in case the target is >2GB away
            unsigned char patch[12] = { 0 };
            patch[0] = 0x48; // REX.W prefix for 64-bit operand
            patch[1] = 0xB8; // MOV RAX, imm64
            *(ULONGLONG*)&patch[2] = (ULONGLONG)&__anti_attach;
            patch[10] = 0xFF; // JMP RAX
            patch[11] = 0xE0;

            SIZE_T bytes_written = 0;
            DbgNtWriteVirtualMemory(process_handle, db_ui_remote_breakin, patch, sizeof(patch), &bytes_written);

            PVOID restore_address = db_ui_remote_breakin;
            SIZE_T restore_size = 12;
            ULONG dummy = 0;
            DbgNtProtectVirtualMemory(process_handle, &restore_address, &restore_size, old_protection, &dummy);

            DbgNtFlushInstructionCache(process_handle, db_ui_remote_breakin, sizeof(patch));
        }
    }

    PVOID dbg_break_point = (PVOID)__get_module("ntdll.dll", "DbgBreakPoint");
    if (dbg_break_point)
    {
        ULONG dw_old_protection = 0;
        PVOID base_address = dbg_break_point;
        SIZE_T region_size = 1;

        if (NT_SUCCESS(DbgNtProtectVirtualMemory(process_handle, &base_address, &region_size, PAGE_EXECUTE_READWRITE, &dw_old_protection)))
        {
            const unsigned char patch[] = { 0xC3 }; // ret
            SIZE_T bytes_written = 0;
            DbgNtWriteVirtualMemory(process_handle, dbg_break_point, (PVOID)patch, sizeof(patch), &bytes_written);

            PVOID restore_address = dbg_break_point;
            SIZE_T restore_size = 1;
            ULONG dummy = 0;
            DbgNtProtectVirtualMemory(process_handle, &restore_address, &restore_size, dw_old_protection, &dummy);

            DbgNtFlushInstructionCache(process_handle, dbg_break_point, sizeof(patch));
        }
    }

    return true;
}