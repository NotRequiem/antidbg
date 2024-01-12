call IsDebuggerPresent    
    test al, al
    jne  being_debugged
    ...
being_debugged:
    push 1
    call ExitProcess