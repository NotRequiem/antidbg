lea rdx, [bDebuggerPresent]
    mov rcx, -1 ; GetCurrentProcess()
    call CheckRemoteDebuggerPresent
    cmp [bDebuggerPresent], 1
    jz being_debugged
    ...
being_debugged:
    mov ecx, -1
    call ExitProcess