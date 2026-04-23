.text

.global DbgNtAccessCheck
DbgNtAccessCheck:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8C22C5FD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWorkerFactoryWorkerReady
DbgNtWorkerFactoryWorkerReady:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x715B47E5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAcceptConnectPort
DbgNtAcceptConnectPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE035FBDA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtMapUserPhysicalPagesScatter
DbgNtMapUserPhysicalPagesScatter:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE18A2AD6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitForSingleObject
DbgNtWaitForSingleObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0B12E409, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCallbackReturn
DbgNtCallbackReturn:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1C867E92, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReadFile
DbgNtReadFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE37EF3CB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeviceIoControlFile
DbgNtDeviceIoControlFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x78E6586C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWriteFile
DbgNtWriteFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAD65E7C3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRemoveIoCompletion
DbgNtRemoveIoCompletion:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x5ED51C79, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReleaseSemaphore
DbgNtReleaseSemaphore:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8A9A7486, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReplyWaitReceivePort
DbgNtReplyWaitReceivePort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xECBFC720, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReplyPort
DbgNtReplyPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x6AF47B58, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationThread
DbgNtSetInformationThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x38080AA1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetEvent
DbgNtSetEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x084935C0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtClose
DbgNtClose:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x00951D2D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryObject
DbgNtQueryObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCC95D518, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationFile
DbgNtQueryInformationFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x96071C10, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenKey
DbgNtOpenKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7AC69BBC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtEnumerateValueKey
DbgNtEnumerateValueKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x49FCABA7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFindAtom
DbgNtFindAtom:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD75BD6C9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryDefaultLocale
DbgNtQueryDefaultLocale:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD158E1CD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryKey
DbgNtQueryKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x77CD5A5E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryValueKey
DbgNtQueryValueKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x29B9362C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAllocateVirtualMemory
DbgNtAllocateVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCBD3E774, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationProcess
DbgNtQueryInformationProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE280F928, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitForMultipleObjects32
DbgNtWaitForMultipleObjects32:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0C812A6E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWriteFileGather
DbgNtWriteFileGather:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0DA2370B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateKey
DbgNtCreateKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x881B6C01, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFreeVirtualMemory
DbgNtFreeVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x831F8B8F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtImpersonateClientOfPort
DbgNtImpersonateClientOfPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xBC317372, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReleaseMutant
DbgNtReleaseMutant:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0C821308, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationToken
DbgNtQueryInformationToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAF9B9530, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRequestWaitReplyPort
DbgNtRequestWaitReplyPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x20B24D6A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryVirtualMemory
DbgNtQueryVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC192D11B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenThreadToken
DbgNtOpenThreadToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB314C1F4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationThread
DbgNtQueryInformationThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x183F44FE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenProcess
DbgNtOpenProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x752F54BA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationFile
DbgNtSetInformationFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x6CD5AAF6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtMapViewOfSection
DbgNtMapViewOfSection:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x76A8543D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAccessCheckAndAuditAlarm
DbgNtAccessCheckAndAuditAlarm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x90551544, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnmapViewOfSection
DbgNtUnmapViewOfSection:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x72AE723D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReplyWaitReceivePortEx
DbgNtReplyWaitReceivePortEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x239EEEDA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtTerminateProcess
DbgNtTerminateProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x07B2062E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetEventBoostPriority
DbgNtSetEventBoostPriority:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1CBB1638, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReadFileScatter
DbgNtReadFileScatter:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA1B26AEE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenThreadTokenEx
DbgNtOpenThreadTokenEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7AE0AFBD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenProcessTokenEx
DbgNtOpenProcessTokenEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE602107C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryPerformanceCounter
DbgNtQueryPerformanceCounter:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCBA4E17C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtEnumerateKey
DbgNtEnumerateKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB93DD4DA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenFile
DbgNtOpenFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF9B8E90D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDelayExecution
DbgNtDelayExecution:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFC483E19, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryDirectoryFile
DbgNtQueryDirectoryFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x252207A4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySystemInformation
DbgNtQuerySystemInformation:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3B6317B9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenSection
DbgNtOpenSection:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x06A6180B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryTimer
DbgNtQueryTimer:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x43974F0A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFsControlFile
DbgNtFsControlFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x983F5E84, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWriteVirtualMemory
DbgNtWriteVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x09970711, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCloseObjectAuditAlarm
DbgNtCloseObjectAuditAlarm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3A930ADE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDuplicateObject
DbgNtDuplicateObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x273E53A1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryAttributesFile
DbgNtQueryAttributesFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3ABB4C26, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtClearEvent
DbgNtClearEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x574C72E4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReadVirtualMemory
DbgNtReadVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0B930717, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenEvent
DbgNtOpenEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x189D7F86, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAdjustPrivilegesToken
DbgNtAdjustPrivilegesToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7DA6EE9A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDuplicateToken
DbgNtDuplicateToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x97A1E323, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtContinue
DbgNtContinue:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x06A6D1EE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryDefaultUILanguage
DbgNtQueryDefaultUILanguage:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1FB1D51C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueueApcThread
DbgNtQueueApcThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFA5FF4ED, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtYieldExecution
DbgNtYieldExecution:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD417DEF3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAddAtom
DbgNtAddAtom:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1C483DD9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateEvent
DbgNtCreateEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB115577F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryVolumeInformationFile
DbgNtQueryVolumeInformationFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA5066F27, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateSection
DbgNtCreateSection:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD08BF015, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFlushBuffersFile
DbgNtFlushBuffersFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x38BBA59E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtApphelpCacheControl
DbgNtApphelpCacheControl:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0197EBD1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateProcessEx
DbgNtCreateProcessEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9FF4AB48, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateThread
DbgNtCreateThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8ED454EA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtIsProcessInJob
DbgNtIsProcessInJob:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x96501A63, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtProtectVirtualMemory
DbgNtProtectVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x07922B07, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySection
DbgNtQuerySection:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFFF0F965, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtResumeThread
DbgNtResumeThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1820429D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtTerminateThread
DbgNtTerminateThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1E5B2C0D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReadRequestData
DbgNtReadRequestData:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9C100826, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateFile
DbgNtCreateFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x6179AFD8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryEvent
DbgNtQueryEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x468C2F58, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWriteRequestData
DbgNtWriteRequestData:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2CB15A26, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenDirectoryObject
DbgNtOpenDirectoryObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x281718AA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAccessCheckByTypeAndAuditAlarm
DbgNtAccessCheckByTypeAndAuditAlarm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x542B46A6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitForMultipleObjects
DbgNtWaitForMultipleObjects:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC122CDA3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationObject
DbgNtSetInformationObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1A242499, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCancelIoFile
DbgNtCancelIoFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1CBAD6EE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtTraceEvent
DbgNtTraceEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xDF74D5E2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPowerInformation
DbgNtPowerInformation:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x376F33F5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetValueKey
DbgNtSetValueKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x06A2E0BD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCancelTimer
DbgNtCancelTimer:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x4FE77548, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetTimer
DbgNtSetTimer:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3D9B1520, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAccessCheckByType
DbgNtAccessCheckByType:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9E78C54C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAccessCheckByTypeResultList
DbgNtAccessCheckByTypeResultList:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE1A4D0E1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAccessCheckByTypeResultListAndAuditAlarm
DbgNtAccessCheckByTypeResultListAndAuditAlarm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x36A999A6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAccessCheckByTypeResultListAndAuditAlarmByHandle
DbgNtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB5B9852C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAcquireProcessActivityReference
DbgNtAcquireProcessActivityReference:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xBA8BBB2E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAddAtomEx
DbgNtAddAtomEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9991D4A4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAddBootEntry
DbgNtAddBootEntry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0998130A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAddDriverEntry
DbgNtAddDriverEntry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8611E6F7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAdjustGroupsToken
DbgNtAdjustGroupsToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x83A600BA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAdjustTokenClaimsAndDeviceGroups
DbgNtAdjustTokenClaimsAndDeviceGroups:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x63F5416D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlertResumeThread
DbgNtAlertResumeThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE4DE2BF5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlertThread
DbgNtAlertThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAC8FA629, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlertThreadByThreadId
DbgNtAlertThreadByThreadId:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x92B235AA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAllocateLocallyUniqueId
DbgNtAllocateLocallyUniqueId:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x73EB14E8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAllocateReserveObject
DbgNtAllocateReserveObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x07181787, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAllocateUserPhysicalPages
DbgNtAllocateUserPhysicalPages:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x331F08B0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAllocateUuids
DbgNtAllocateUuids:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x6BEAFBE5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAllocateVirtualMemoryEx
DbgNtAllocateVirtualMemoryEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB4A36EE1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcAcceptConnectPort
DbgNtAlpcAcceptConnectPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE4B3DFFC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcCancelMessage
DbgNtAlpcCancelMessage:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x93305F81, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcConnectPort
DbgNtAlpcConnectPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x5E80BFDE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcConnectPortEx
DbgNtAlpcConnectPortEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x615EDD9A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcCreatePort
DbgNtAlpcCreatePort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x20B02538, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcCreatePortSection
DbgNtAlpcCreatePortSection:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFB63C7CA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcCreateResourceReserve
DbgNtAlpcCreateResourceReserve:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x77663852, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcCreateSectionView
DbgNtAlpcCreateSectionView:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF4ABF335, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcCreateSecurityContext
DbgNtAlpcCreateSecurityContext:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x22A33520, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcDeletePortSection
DbgNtAlpcDeletePortSection:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD68BFCCF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcDeleteResourceReserve
DbgNtAlpcDeleteResourceReserve:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x5CA4B827, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcDeleteSectionView
DbgNtAlpcDeleteSectionView:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x28B43D2B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcDeleteSecurityContext
DbgNtAlpcDeleteSecurityContext:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9E4B9BC2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcDisconnectPort
DbgNtAlpcDisconnectPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x22B23F1A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcImpersonateClientContainerOfPort
DbgNtAlpcImpersonateClientContainerOfPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x20B2D1E8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcImpersonateClientOfPort
DbgNtAlpcImpersonateClientOfPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xBB30BCA3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcOpenSenderProcess
DbgNtAlpcOpenSenderProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF1ADE843, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcOpenSenderThread
DbgNtAlpcOpenSenderThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1AB5C40F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcQueryInformation
DbgNtAlpcQueryInformation:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x5CCC5A59, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcQueryInformationMessage
DbgNtAlpcQueryInformationMessage:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x07B0D888, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcRevokeSecurityContext
DbgNtAlpcRevokeSecurityContext:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x4E9A793A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcSendWaitReceivePort
DbgNtAlpcSendWaitReceivePort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x26B7C1DC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAlpcSetInformation
DbgNtAlpcSetInformation:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1EB85C6D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAreMappedFilesTheSame
DbgNtAreMappedFilesTheSame:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA42EA1B7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAssignProcessToJobObject
DbgNtAssignProcessToJobObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF9560818, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAssociateWaitCompletionPacket
DbgNtAssociateWaitCompletionPacket:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0D3477DA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCallEnclave
DbgNtCallEnclave:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0AACC180, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCancelIoFileEx
DbgNtCancelIoFileEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCE55170B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCancelSynchronousIoFile
DbgNtCancelSynchronousIoFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1E543282, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCancelTimer2
DbgNtCancelTimer2:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x07A8DC25, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCancelWaitCompletionPacket
DbgNtCancelWaitCompletionPacket:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x396C1FDE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCommitComplete
DbgNtCommitComplete:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x269D3636, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCommitEnlistment
DbgNtCommitEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB923F0F1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCommitRegistryTransaction
DbgNtCommitRegistryTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9E30B8A5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCommitTransaction
DbgNtCommitTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x96CC5491, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCompactKeys
DbgNtCompactKeys:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x23B62600, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCompareObjects
DbgNtCompareObjects:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAE3D90FE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCompareSigningLevels
DbgNtCompareSigningLevels:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x32E8006E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCompareTokens
DbgNtCompareTokens:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7DD51731, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCompleteConnectPort
DbgNtCompleteConnectPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x64B2411C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCompressKey
DbgNtCompressKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x88155B4E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtConnectPort
DbgNtConnectPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7AF5796A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtConvertBetweenAuxiliaryCounterAndPerformanceCounter
DbgNtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2FA0473B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateDebugObject
DbgNtCreateDebugObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x16BF6A77, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateDirectoryObject
DbgNtCreateDirectoryObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x98A9A0E5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateDirectoryObjectEx
DbgNtCreateDirectoryObjectEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB24DF6F0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateEnclave
DbgNtCreateEnclave:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD1ACF97F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateEnlistment
DbgNtCreateEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x07C519AF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateEventPair
DbgNtCreateEventPair:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x80D2AE0A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateIRTimer
DbgNtCreateIRTimer:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x23931934, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateIoCompletion
DbgNtCreateIoCompletion:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x920B9699, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateJobObject
DbgNtCreateJobObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x16BCC1E7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateJobSet
DbgNtCreateJobSet:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8009F8E5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateKeyTransacted
DbgNtCreateKeyTransacted:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9EC115EF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateKeyedEvent
DbgNtCreateKeyedEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x74AE0F48, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateLowBoxToken
DbgNtCreateLowBoxToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAF1AF5B2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateMailslotFile
DbgNtCreateMailslotFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3D9CACA8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateMutant
DbgNtCreateMutant:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x32AC353E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateNamedPipeFile
DbgNtCreateNamedPipeFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x74BB4A68, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreatePagingFile
DbgNtCreatePagingFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xACFD5EAA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreatePartition
DbgNtCreatePartition:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x04B26421, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreatePort
DbgNtCreatePort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF57FE8F7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreatePrivateNamespace
DbgNtCreatePrivateNamespace:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x88D649FB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateProcess
DbgNtCreateProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x5B99246A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateProfile
DbgNtCreateProfile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x34A27A0A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateProfileEx
DbgNtCreateProfileEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x42A9BCDF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateRegistryTransaction
DbgNtCreateRegistryTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0C902C01, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateResourceManager
DbgNtCreateResourceManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8132D3EE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateSemaphore
DbgNtCreateSemaphore:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x188F4436, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateSymbolicLinkObject
DbgNtCreateSymbolicLinkObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x44DE4243, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateThreadEx
DbgNtCreateThreadEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD03F0E79, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateTimer
DbgNtCreateTimer:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9A1FA093, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateTimer2
DbgNtCreateTimer2:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0985895B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateToken
DbgNtCreateToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x43DC4F46, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateTokenEx
DbgNtCreateTokenEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7A9D3866, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateTransaction
DbgNtCreateTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC4E5E2B1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateTransactionManager
DbgNtCreateTransactionManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9E29B2BB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateUserProcess
DbgNtCreateUserProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE2B3C32F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateWaitCompletionPacket
DbgNtCreateWaitCompletionPacket:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFFA1FB31, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateWaitablePort
DbgNtCreateWaitablePort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA476C9EE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateWnfStateName
DbgNtCreateWnfStateName:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFADAD54E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateWorkerFactory
DbgNtCreateWorkerFactory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3893D4F4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDebugActiveProcess
DbgNtDebugActiveProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0FA5083E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDebugContinue
DbgNtDebugContinue:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF25DFDF2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteAtom
DbgNtDeleteAtom:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1AC90740, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteBootEntry
DbgNtDeleteBootEntry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8C10F4E1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteDriverEntry
DbgNtDeleteDriverEntry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC191DF16, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteFile
DbgNtDeleteFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x73DBECE9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteKey
DbgNtDeleteKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x06D2E6AC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteObjectAuditAlarm
DbgNtDeleteObjectAuditAlarm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x36993E06, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeletePrivateNamespace
DbgNtDeletePrivateNamespace:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x16AFDFFB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteValueKey
DbgNtDeleteValueKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCEF32DA8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteWnfStateData
DbgNtDeleteWnfStateData:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xBE058A52, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDeleteWnfStateName
DbgNtDeleteWnfStateName:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x940BBF8D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDisableLastKnownGood
DbgNtDisableLastKnownGood:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x68D92A7E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDisplayString
DbgNtDisplayString:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCED8F25D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtDrawText
DbgNtDrawText:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC131FAB7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtEnableLastKnownGood
DbgNtEnableLastKnownGood:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x79EF7544, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtEnumerateBootEntries
DbgNtEnumerateBootEntries:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAC8CC774, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtEnumerateDriverEntries
DbgNtEnumerateDriverEntries:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAC97B41C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtEnumerateSystemEnvironmentValuesEx
DbgNtEnumerateSystemEnvironmentValuesEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x172B5BDF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtEnumerateTransactionObject
DbgNtEnumerateTransactionObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1A38F344, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtExtendSection
DbgNtExtendSection:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x544D76D9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFilterBootOption
DbgNtFilterBootOption:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9C979F0A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFilterToken
DbgNtFilterToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x6DB15D10, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFilterTokenEx
DbgNtFilterTokenEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x28A2F6F4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFlushBuffersFileEx
DbgNtFlushBuffersFileEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1D2457F7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFlushInstallUILanguage
DbgNtFlushInstallUILanguage:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC457F38B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFlushInstructionCache
DbgNtFlushInstructionCache:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1C3A5EE3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFlushKey
DbgNtFlushKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x87B49A20, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFlushProcessWriteBuffers
DbgNtFlushProcessWriteBuffers:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x44E47854, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFlushVirtualMemory
DbgNtFlushVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFD6F1903, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFlushWriteBuffer
DbgNtFlushWriteBuffer:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x032B6BD2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFreeUserPhysicalPages
DbgNtFreeUserPhysicalPages:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x09B83234, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFreezeRegistry
DbgNtFreezeRegistry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x4CED467D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtFreezeTransactions
DbgNtFreezeTransactions:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCC12D49E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetCachedSigningLevel
DbgNtGetCachedSigningLevel:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2C996244, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetCompleteWnfStateSubscription
DbgNtGetCompleteWnfStateSubscription:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x736931B9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetContextThread
DbgNtGetContextThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x74582EE1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetCurrentProcessorNumber
DbgNtGetCurrentProcessorNumber:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8698F25A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetCurrentProcessorNumberEx
DbgNtGetCurrentProcessorNumberEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7CC385BD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetDevicePowerState
DbgNtGetDevicePowerState:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCE4DFEE6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetMUIRegistryInfo
DbgNtGetMUIRegistryInfo:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD47D1821, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetNextProcess
DbgNtGetNextProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x4D2742BC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetNextThread
DbgNtGetNextThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0EBDFEEE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetNlsSectionPtr
DbgNtGetNlsSectionPtr:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x22122B89, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetNotificationResourceManager
DbgNtGetNotificationResourceManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCE11D2BF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtGetWriteWatch
DbgNtGetWriteWatch:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8CC3B99E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtImpersonateAnonymousToken
DbgNtImpersonateAnonymousToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x61D536EC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtImpersonateThread
DbgNtImpersonateThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x722AAC90, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtInitializeEnclave
DbgNtInitializeEnclave:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x26DE4FDC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtInitializeNlsFiles
DbgNtInitializeNlsFiles:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x80BAAF18, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtInitializeRegistry
DbgNtInitializeRegistry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x14893A1D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtInitiatePowerAction
DbgNtInitiatePowerAction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xBC24937D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtIsSystemResumeAutomatic
DbgNtIsSystemResumeAutomatic:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x178150A3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtIsUILanguageComitted
DbgNtIsUILanguageComitted:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xDE621FDF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtListenPort
DbgNtListenPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAEB2AB38, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLoadDriver
DbgNtLoadDriver:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x947DCD56, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLoadEnclaveData
DbgNtLoadEnclaveData:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD00B4338, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLoadHotPatch
DbgNtLoadHotPatch:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFC63F3F4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLoadKey
DbgNtLoadKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF55EC4E6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLoadKey2
DbgNtLoadKey2:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x13AA49AE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLoadKeyEx
DbgNtLoadKeyEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8BB945FE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLockFile
DbgNtLockFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE372EDE7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLockProductActivationKeys
DbgNtLockProductActivationKeys:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3797203C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLockRegistryKey
DbgNtLockRegistryKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0229FF2D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtLockVirtualMemory
DbgNtLockVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC05D2530, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtMakePermanentObject
DbgNtMakePermanentObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x253543E7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtMakeTemporaryObject
DbgNtMakeTemporaryObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x85BDAB07, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtManagePartition
DbgNtManagePartition:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0EA00E33, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtMapCMFModule
DbgNtMapCMFModule:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x6EC17246, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtMapUserPhysicalPages
DbgNtMapUserPhysicalPages:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x02A49BB0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtMapViewOfSectionEx
DbgNtMapViewOfSectionEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAE956DCF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtModifyBootEntry
DbgNtModifyBootEntry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1D9B0F00, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtModifyDriverEntry
DbgNtModifyDriverEntry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0B963CD8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtNotifyChangeDirectoryFile
DbgNtNotifyChangeDirectoryFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA4838418, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtNotifyChangeDirectoryFileEx
DbgNtNotifyChangeDirectoryFileEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x809B04A7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtNotifyChangeKey
DbgNtNotifyChangeKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC93FD0AC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtNotifyChangeMultipleKeys
DbgNtNotifyChangeMultipleKeys:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAD16BE90, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtNotifyChangeSession
DbgNtNotifyChangeSession:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9651A4F1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenEnlistment
DbgNtOpenEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF9650D02, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenEventPair
DbgNtOpenEventPair:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x40134C8D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenIoCompletion
DbgNtOpenIoCompletion:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x93059590, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenJobObject
DbgNtOpenJobObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x04B9EDC5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenKeyEx
DbgNtOpenKeyEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x597B5FC6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenKeyTransacted
DbgNtOpenKeyTransacted:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA49B5C86, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenKeyTransactedEx
DbgNtOpenKeyTransactedEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC81C0A46, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenKeyedEvent
DbgNtOpenKeyedEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x4ED56D42, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenMutant
DbgNtOpenMutant:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x34B27378, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenObjectAuditAlarm
DbgNtOpenObjectAuditAlarm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3E9ED8CA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenPartition
DbgNtOpenPartition:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x414A21D9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenPrivateNamespace
DbgNtOpenPrivateNamespace:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xBF13C08A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenProcessToken
DbgNtOpenProcessToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9DA0F3A0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenRegistryTransaction
DbgNtOpenRegistryTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x5E987005, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenResourceManager
DbgNtOpenResourceManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3BA1436A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenSemaphore
DbgNtOpenSemaphore:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0A9A33C6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenSession
DbgNtOpenSession:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC707DB84, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenSymbolicLinkObject
DbgNtOpenSymbolicLinkObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA638C0E5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenThread
DbgNtOpenThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7EAA7E09, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenTimer
DbgNtOpenTimer:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC9983FE0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenTransaction
DbgNtOpenTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x63487FFB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtOpenTransactionManager
DbgNtOpenTransactionManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1840C00A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPlugPlayControl
DbgNtPlugPlayControl:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x09DA0D41, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPrePrepareComplete
DbgNtPrePrepareComplete:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3AA7C8B8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPrePrepareEnlistment
DbgNtPrePrepareEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF9A105D2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPrepareComplete
DbgNtPrepareComplete:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x28B04FB2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPrepareEnlistment
DbgNtPrepareEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x09A72475, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPrivilegeCheck
DbgNtPrivilegeCheck:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2685FBC7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPrivilegeObjectAuditAlarm
DbgNtPrivilegeObjectAuditAlarm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA5211F77, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPrivilegedServiceAuditAlarm
DbgNtPrivilegedServiceAuditAlarm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB0A25233, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPropagationComplete
DbgNtPropagationComplete:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9B2461B9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPropagationFailed
DbgNtPropagationFailed:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x201B50CE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPulseEvent
DbgNtPulseEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x182A2DE2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryAuxiliaryCounterFrequency
DbgNtQueryAuxiliaryCounterFrequency:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAA19C7FC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryBootEntryOrder
DbgNtQueryBootEntryOrder:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF357FDCB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryBootOptions
DbgNtQueryBootOptions:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x4BA53149, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryDebugFilterState
DbgNtQueryDebugFilterState:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x02942A1A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryDirectoryFileEx
DbgNtQueryDirectoryFileEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x38874205, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryDirectoryObject
DbgNtQueryDirectoryObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x02A3F5A3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryDriverEntryOrder
DbgNtQueryDriverEntryOrder:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2409EF53, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryEaFile
DbgNtQueryEaFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x58F3A6AA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryFullAttributesFile
DbgNtQueryFullAttributesFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA604B6AE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationAtom
DbgNtQueryInformationAtom:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB621DBA0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationByName
DbgNtQueryInformationByName:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3CD84F0F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationEnlistment
DbgNtQueryInformationEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAB25AEB3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationJobObject
DbgNtQueryInformationJobObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8892F618, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationPort
DbgNtQueryInformationPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB22CD7BE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationResourceManager
DbgNtQueryInformationResourceManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9330A190, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationTransaction
DbgNtQueryInformationTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x02950E0F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationTransactionManager
DbgNtQueryInformationTransactionManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x05B69396, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInformationWorkerFactory
DbgNtQueryInformationWorkerFactory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0D5E1BD0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryInstallUILanguage
DbgNtQueryInstallUILanguage:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE85BFBE3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryIntervalProfile
DbgNtQueryIntervalProfile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8CB80F9F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryIoCompletion
DbgNtQueryIoCompletion:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x48636A37, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryLicenseValue
DbgNtQueryLicenseValue:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0C5B17E4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryMultipleValueKey
DbgNtQueryMultipleValueKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x962F7737, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryMutant
DbgNtQueryMutant:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x12B21B26, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryOpenSubKeys
DbgNtQueryOpenSubKeys:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAAD18175, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryOpenSubKeysEx
DbgNtQueryOpenSubKeysEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB5A5EB62, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryPortInformationProcess
DbgNtQueryPortInformationProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x832D9AA0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryQuotaInformationFile
DbgNtQueryQuotaInformationFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFE6FF0FC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySecurityAttributesToken
DbgNtQuerySecurityAttributesToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2B8A110E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySecurityObject
DbgNtQuerySecurityObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFC783F27, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySecurityPolicy
DbgNtQuerySecurityPolicy:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x963DABF9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySemaphore
DbgNtQuerySemaphore:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x608849C4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySymbolicLinkObject
DbgNtQuerySymbolicLinkObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0581777E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySystemEnvironmentValue
DbgNtQuerySystemEnvironmentValue:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB3A92296, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySystemEnvironmentValueEx
DbgNtQuerySystemEnvironmentValueEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1D3855F8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySystemInformationEx
DbgNtQuerySystemInformationEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2CDA5628, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryTimerResolution
DbgNtQueryTimerResolution:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x18B6DD9D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryWnfStateData
DbgNtQueryWnfStateData:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2F00B121, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueryWnfStateNameInformation
DbgNtQueryWnfStateNameInformation:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x949A6F8E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQueueApcThreadEx
DbgNtQueueApcThreadEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8CB142C6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRaiseException
DbgNtRaiseException:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x76329421, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRaiseHardError
DbgNtRaiseHardError:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xDF8EFADD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReadOnlyEnlistment
DbgNtReadOnlyEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1A2710B1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRecoverEnlistment
DbgNtRecoverEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD946FEDD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRecoverResourceManager
DbgNtRecoverResourceManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE3B2749B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRecoverTransactionManager
DbgNtRecoverTransactionManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x87339198, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRegisterProtocolAddressInformation
DbgNtRegisterProtocolAddressInformation:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1D8B0318, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRegisterThreadTerminatePort
DbgNtRegisterThreadTerminatePort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE4B1DF1F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReleaseKeyedEvent
DbgNtReleaseKeyedEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0A8F1302, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReleaseWorkerFactoryWorker
DbgNtReleaseWorkerFactoryWorker:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x604916AD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRemoveIoCompletionEx
DbgNtRemoveIoCompletionEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x58AD0478, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRemoveProcessDebug
DbgNtRemoveProcessDebug:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8A2B9D9A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRenameKey
DbgNtRenameKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCDF0D268, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRenameTransactionManager
DbgNtRenameTransactionManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1A4002CA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReplaceKey
DbgNtReplaceKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x16A2C2F1, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReplacePartitionUnit
DbgNtReplacePartitionUnit:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFB7BDF23, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReplyWaitReplyPort
DbgNtReplyWaitReplyPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA0319F9A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRequestPort
DbgNtRequestPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE572E2E9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtResetEvent
DbgNtResetEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0AA82B1C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtResetWriteWatch
DbgNtResetWriteWatch:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3CBF4A62, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRestoreKey
DbgNtRestoreKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x06DAF6A0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtResumeProcess
DbgNtResumeProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB52ECAC4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRevertContainerImpersonation
DbgNtRevertContainerImpersonation:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x089F060F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRollbackComplete
DbgNtRollbackComplete:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x483558BE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRollbackEnlistment
DbgNtRollbackEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x01DF1C5D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRollbackRegistryTransaction
DbgNtRollbackRegistryTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC8922E02, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRollbackTransaction
DbgNtRollbackTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x06992409, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRollforwardTransactionManager
DbgNtRollforwardTransactionManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1B2269C2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSaveKey
DbgNtSaveKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x6BBF86D9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSaveKeyEx
DbgNtSaveKeyEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x296111A6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSaveMergedKeys
DbgNtSaveMergedKeys:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8737BCA0, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSecureConnectPort
DbgNtSecureConnectPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x66FF796C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSerializeBoot
DbgNtSerializeBoot:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAB3E6078, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetBootEntryOrder
DbgNtSetBootEntryOrder:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD7CDC76F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetBootOptions
DbgNtSetBootOptions:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xDF9B0CDC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetCachedSigningLevel
DbgNtSetCachedSigningLevel:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD61A94A4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetCachedSigningLevel2
DbgNtSetCachedSigningLevel2:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x72CD5DDC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetContextThread
DbgNtSetContextThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9430D695, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetDebugFilterState
DbgNtSetDebugFilterState:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x548DB2CC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetDefaultHardErrorPort
DbgNtSetDefaultHardErrorPort:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x268E271C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetDefaultLocale
DbgNtSetDefaultLocale:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x67AF117D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetDefaultUILanguage
DbgNtSetDefaultUILanguage:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9FBC9824, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetDriverEntryOrder
DbgNtSetDriverEntryOrder:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x131675E3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetEaFile
DbgNtSetEaFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0215EC1E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetHighEventPair
DbgNtSetHighEventPair:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC64F869D, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetHighWaitLowEventPair
DbgNtSetHighWaitLowEventPair:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x70D66C5F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetIRTimer
DbgNtSetIRTimer:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x035F220C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationDebugObject
DbgNtSetInformationDebugObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF3590553, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationEnlistment
DbgNtSetInformationEnlistment:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2A3233A6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationJobObject
DbgNtSetInformationJobObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xBA85DA18, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationKey
DbgNtSetInformationKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1CE20F79, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationResourceManager
DbgNtSetInformationResourceManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0BB2E8C3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationSymbolicLink
DbgNtSetInformationSymbolicLink:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xEE7BE6EE, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationToken
DbgNtSetInformationToken:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8D92F71A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationTransaction
DbgNtSetInformationTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF0B9DE65, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationTransactionManager
DbgNtSetInformationTransactionManager:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x015427EC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationVirtualMemory
DbgNtSetInformationVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0D9F415B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationWorkerFactory
DbgNtSetInformationWorkerFactory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x865790CA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetIntervalProfile
DbgNtSetIntervalProfile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC582BB58, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetIoCompletion
DbgNtSetIoCompletion:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x06EC263F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetIoCompletionEx
DbgNtSetIoCompletionEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x38D37416, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetLdtEntries
DbgNtSetLdtEntries:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA80DC1E9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetLowEventPair
DbgNtSetLowEventPair:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2F30AF27, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetLowWaitHighEventPair
DbgNtSetLowWaitHighEventPair:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x96B25AEF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetQuotaInformationFile
DbgNtSetQuotaInformationFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xAB36AB93, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetSecurityObject
DbgNtSetSecurityObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8CA7A43B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetSystemEnvironmentValue
DbgNtSetSystemEnvironmentValue:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFC3B2C80, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetSystemEnvironmentValueEx
DbgNtSetSystemEnvironmentValueEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x40BB0C00, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetSystemInformation
DbgNtSetSystemInformation:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xDC4680EB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetSystemPowerState
DbgNtSetSystemPowerState:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x36380EA7, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetSystemTime
DbgNtSetSystemTime:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2EAA2F37, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetThreadExecutionState
DbgNtSetThreadExecutionState:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x02AD7C28, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetTimer2
DbgNtSetTimer2:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1DA6FCB9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetTimerEx
DbgNtSetTimerEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB2B8FC7E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetTimerResolution
DbgNtSetTimerResolution:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCA5C0401, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetUuidSeed
DbgNtSetUuidSeed:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x87ADCF81, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetVolumeInformationFile
DbgNtSetVolumeInformationFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE577F1CB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetWnfProcessNotificationEvent
DbgNtSetWnfProcessNotificationEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x30BA0D72, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtShutdownSystem
DbgNtShutdownSystem:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x22801F50, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtShutdownWorkerFactory
DbgNtShutdownWorkerFactory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x02962A38, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSignalAndWaitForSingleObject
DbgNtSignalAndWaitForSingleObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x85959509, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSinglePhaseReject
DbgNtSinglePhaseReject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x882798BB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtStartProfile
DbgNtStartProfile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF095FB33, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtStopProfile
DbgNtStopProfile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x67A699FD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSubscribeWnfStateChange
DbgNtSubscribeWnfStateChange:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x44E15944, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSuspendProcess
DbgNtSuspendProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCE20D7AF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSuspendThread
DbgNtSuspendThread:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE73FEF94, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSystemDebugControl
DbgNtSystemDebugControl:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC397CD05, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtTerminateEnclave
DbgNtTerminateEnclave:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x74D3627E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtTerminateJobObject
DbgNtTerminateJobObject:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x8BA5B9EB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtTestAlert
DbgNtTestAlert:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1E3727BA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtThawRegistry
DbgNtThawRegistry:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC24DD723, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtThawTransactions
DbgNtThawTransactions:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7FA5673F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtTraceControl
DbgNtTraceControl:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xB41B300A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtTranslateFilePath
DbgNtTranslateFilePath:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x56EC7360, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUmsThreadYield
DbgNtUmsThreadYield:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xEA566373, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnloadDriver
DbgNtUnloadDriver:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0EC75E06, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnloadKey
DbgNtUnloadKey:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x09DFE8A8, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnloadKey2
DbgNtUnloadKey2:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xA1D66544, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnloadKeyEx
DbgNtUnloadKeyEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xFB742C28, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnlockFile
DbgNtUnlockFile:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3E37402C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnlockVirtualMemory
DbgNtUnlockVirtualMemory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0791111F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnmapViewOfSectionEx
DbgNtUnmapViewOfSectionEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x809357CD, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUnsubscribeWnfStateChange
DbgNtUnsubscribeWnfStateChange:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF85DDE04, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtUpdateWnfStateData
DbgNtUpdateWnfStateData:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2D04B739, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtVdmControl
DbgNtVdmControl:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x03940707, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitForAlertByThreadId
DbgNtWaitForAlertByThreadId:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x7AAF9ED4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitForDebugEvent
DbgNtWaitForDebugEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCA40E3D2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitForKeyedEvent
DbgNtWaitForKeyedEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3A917D5A, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitForWorkViaWorkerFactory
DbgNtWaitForWorkViaWorkerFactory:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9C8AE07F, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitHighEventPair
DbgNtWaitHighEventPair:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2EB1AAA4, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitLowEventPair
DbgNtWaitLowEventPair:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x61D3FAF6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtAcquireCMFViewOwnership
DbgNtAcquireCMFViewOwnership:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x9D42C3EB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCancelDeviceWakeupRequest
DbgNtCancelDeviceWakeupRequest:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x5F85511E, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtClearAllSavepointsTransaction
DbgNtClearAllSavepointsTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xE04BE0D9, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtClearSavepointTransaction
DbgNtClearSavepointTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF850E6C3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRollbackSavepointTransaction
DbgNtRollbackSavepointTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x970FF006, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSavepointTransaction
DbgNtSavepointTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD04BF6DB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSavepointComplete
DbgNtSavepointComplete:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCD4222CA, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateSectionEx
DbgNtCreateSectionEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x2C9FEFC5, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtCreateCrossVmEvent
DbgNtCreateCrossVmEvent:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x40044D94, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtListTransactions
DbgNtListTransactions:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x1B8904E3, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtMarshallTransaction
DbgNtMarshallTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCB24EBB6, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtPullTransaction
DbgNtPullTransaction:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xC28AE05B, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtReleaseCMFViewOwnership
DbgNtReleaseCMFViewOwnership:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF22CDCF2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtWaitForWnfNotifications
DbgNtWaitForWnfNotifications:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x0DDF2E89, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtStartTm
DbgNtStartTm:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x3F925D6C, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtSetInformationProcess
DbgNtSetInformationProcess:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x811F9F74, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRequestDeviceWakeup
DbgNtRequestDeviceWakeup:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xCD950BC2, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtRequestWakeupLatency
DbgNtRequestWakeupLatency:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0x035B28CF, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtQuerySystemTime
DbgNtQuerySystemTime:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF46FFDCB, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtManageHotPatch
DbgNtManageHotPatch:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xF549F9FC, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret

.global DbgNtContinueEx
DbgNtContinueEx:
    movq %rcx, 8(%rsp)
    movq %rdx, 16(%rsp)
    movq %r8, 24(%rsp)
    movq %r9, 32(%rsp)
    subq $0x28, %rsp
    movl $0xD7493035, %ecx
    call __adbg_syscall
    addq $0x28, %rsp
    movq 8(%rsp), %rcx
    movq 16(%rsp), %rdx
    movq 24(%rsp), %r8
    movq 32(%rsp), %r9
    movq %rcx, %r10
    syscall
    ret
