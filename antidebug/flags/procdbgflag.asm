lea rcx, [dwReturned]
    push rcx     ; ReturnLength
    mov r9d, 4   ; ProcessInformationLength
    lea r8, [dwProcessDebugFlags] 
                 ; ProcessInformation
    mov edx, 1Fh ; ProcessInformationClass
    mov rcx, -1  ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [dwProcessDebugFlags], 0
    jz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess