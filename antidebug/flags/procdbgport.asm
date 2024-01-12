lea rcx, [dwReturned]
    push rcx    ; ReturnLength
    mov r9d, 4  ; ProcessInformationLength
    lea r8, [dwProcessDebugPort] 
                ; ProcessInformation
    mov edx, 7  ; ProcessInformationClass
    mov rcx, -1 ; ProcessHandle
    call NtQueryInformationProcess
    cmp dword ptr [dwProcessDebugPort], -1
    jz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess