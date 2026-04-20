.text

.global DbgNtAccessCheck
.type DbgNtAccessCheck, @function
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
.type DbgNtWorkerFactoryWorkerReady, @function
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
.type DbgNtAcceptConnectPort, @function
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
.type DbgNtMapUserPhysicalPagesScatter, @function
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
.type DbgNtWaitForSingleObject, @function
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
.type DbgNtCallbackReturn, @function
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
.type DbgNtReadFile, @function
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
.type DbgNtDeviceIoControlFile, @function
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
.type DbgNtWriteFile, @function
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
.type DbgNtRemoveIoCompletion, @function
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
.type DbgNtReleaseSemaphore, @function
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
.type DbgNtReplyWaitReceivePort, @function
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
.type DbgNtReplyPort, @function
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
.type DbgNtSetInformationThread, @function
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
.type DbgNtSetEvent, @function
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
.type DbgNtClose, @function
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
.type DbgNtQueryObject, @function
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
.type DbgNtQueryInformationFile, @function
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
.type DbgNtOpenKey, @function
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
.type DbgNtEnumerateValueKey, @function
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
.type DbgNtFindAtom, @function
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
.type DbgNtQueryDefaultLocale, @function
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
.type DbgNtQueryKey, @function
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
.type DbgNtQueryValueKey, @function
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
.type DbgNtAllocateVirtualMemory, @function
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
.type DbgNtQueryInformationProcess, @function
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
.type DbgNtWaitForMultipleObjects32, @function
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
.type DbgNtWriteFileGather, @function
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
.type DbgNtCreateKey, @function
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
.type DbgNtFreeVirtualMemory, @function
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
.type DbgNtImpersonateClientOfPort, @function
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
.type DbgNtReleaseMutant, @function
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
.type DbgNtQueryInformationToken, @function
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
.type DbgNtRequestWaitReplyPort, @function
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
.type DbgNtQueryVirtualMemory, @function
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
.type DbgNtOpenThreadToken, @function
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
.type DbgNtQueryInformationThread, @function
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
.type DbgNtOpenProcess, @function
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
.type DbgNtSetInformationFile, @function
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
.type DbgNtMapViewOfSection, @function
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
.type DbgNtAccessCheckAndAuditAlarm, @function
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
.type DbgNtUnmapViewOfSection, @function
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
.type DbgNtReplyWaitReceivePortEx, @function
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
.type DbgNtTerminateProcess, @function
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
.type DbgNtSetEventBoostPriority, @function
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
.type DbgNtReadFileScatter, @function
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
.type DbgNtOpenThreadTokenEx, @function
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
.type DbgNtOpenProcessTokenEx, @function
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
.type DbgNtQueryPerformanceCounter, @function
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
.type DbgNtEnumerateKey, @function
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
.type DbgNtOpenFile, @function
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
.type DbgNtDelayExecution, @function
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
.type DbgNtQueryDirectoryFile, @function
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
.type DbgNtQuerySystemInformation, @function
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
.type DbgNtOpenSection, @function
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
.type DbgNtQueryTimer, @function
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
.type DbgNtFsControlFile, @function
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
.type DbgNtWriteVirtualMemory, @function
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
.type DbgNtCloseObjectAuditAlarm, @function
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
.type DbgNtDuplicateObject, @function
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
.type DbgNtQueryAttributesFile, @function
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
.type DbgNtClearEvent, @function
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
.type DbgNtReadVirtualMemory, @function
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
.type DbgNtOpenEvent, @function
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
.type DbgNtAdjustPrivilegesToken, @function
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
.type DbgNtDuplicateToken, @function
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
.type DbgNtContinue, @function
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
.type DbgNtQueryDefaultUILanguage, @function
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
.type DbgNtQueueApcThread, @function
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
.type DbgNtYieldExecution, @function
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
.type DbgNtAddAtom, @function
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
.type DbgNtCreateEvent, @function
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
.type DbgNtQueryVolumeInformationFile, @function
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
.type DbgNtCreateSection, @function
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
.type DbgNtFlushBuffersFile, @function
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
.type DbgNtApphelpCacheControl, @function
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
.type DbgNtCreateProcessEx, @function
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
.type DbgNtCreateThread, @function
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
.type DbgNtIsProcessInJob, @function
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
.type DbgNtProtectVirtualMemory, @function
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
.type DbgNtQuerySection, @function
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
.type DbgNtResumeThread, @function
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
.type DbgNtTerminateThread, @function
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
.type DbgNtReadRequestData, @function
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
.type DbgNtCreateFile, @function
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
.type DbgNtQueryEvent, @function
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
.type DbgNtWriteRequestData, @function
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
.type DbgNtOpenDirectoryObject, @function
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
.type DbgNtAccessCheckByTypeAndAuditAlarm, @function
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
.type DbgNtWaitForMultipleObjects, @function
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
.type DbgNtSetInformationObject, @function
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
.type DbgNtCancelIoFile, @function
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
.type DbgNtTraceEvent, @function
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
.type DbgNtPowerInformation, @function
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
.type DbgNtSetValueKey, @function
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
.type DbgNtCancelTimer, @function
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
.type DbgNtSetTimer, @function
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
.type DbgNtAccessCheckByType, @function
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
.type DbgNtAccessCheckByTypeResultList, @function
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
.type DbgNtAccessCheckByTypeResultListAndAuditAlarm, @function
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
.type DbgNtAccessCheckByTypeResultListAndAuditAlarmByHandle, @function
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
.type DbgNtAcquireProcessActivityReference, @function
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
.type DbgNtAddAtomEx, @function
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
.type DbgNtAddBootEntry, @function
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
.type DbgNtAddDriverEntry, @function
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
.type DbgNtAdjustGroupsToken, @function
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
.type DbgNtAdjustTokenClaimsAndDeviceGroups, @function
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
.type DbgNtAlertResumeThread, @function
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
.type DbgNtAlertThread, @function
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
.type DbgNtAlertThreadByThreadId, @function
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
.type DbgNtAllocateLocallyUniqueId, @function
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
.type DbgNtAllocateReserveObject, @function
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
.type DbgNtAllocateUserPhysicalPages, @function
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
.type DbgNtAllocateUuids, @function
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
.type DbgNtAllocateVirtualMemoryEx, @function
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
.type DbgNtAlpcAcceptConnectPort, @function
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
.type DbgNtAlpcCancelMessage, @function
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
.type DbgNtAlpcConnectPort, @function
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
.type DbgNtAlpcConnectPortEx, @function
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
.type DbgNtAlpcCreatePort, @function
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
.type DbgNtAlpcCreatePortSection, @function
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
.type DbgNtAlpcCreateResourceReserve, @function
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
.type DbgNtAlpcCreateSectionView, @function
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
.type DbgNtAlpcCreateSecurityContext, @function
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
.type DbgNtAlpcDeletePortSection, @function
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
.type DbgNtAlpcDeleteResourceReserve, @function
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
.type DbgNtAlpcDeleteSectionView, @function
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
.type DbgNtAlpcDeleteSecurityContext, @function
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
.type DbgNtAlpcDisconnectPort, @function
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
.type DbgNtAlpcImpersonateClientContainerOfPort, @function
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
.type DbgNtAlpcImpersonateClientOfPort, @function
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
.type DbgNtAlpcOpenSenderProcess, @function
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
.type DbgNtAlpcOpenSenderThread, @function
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
.type DbgNtAlpcQueryInformation, @function
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
.type DbgNtAlpcQueryInformationMessage, @function
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
.type DbgNtAlpcRevokeSecurityContext, @function
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
.type DbgNtAlpcSendWaitReceivePort, @function
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
.type DbgNtAlpcSetInformation, @function
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
.type DbgNtAreMappedFilesTheSame, @function
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
.type DbgNtAssignProcessToJobObject, @function
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
.type DbgNtAssociateWaitCompletionPacket, @function
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
.type DbgNtCallEnclave, @function
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
.type DbgNtCancelIoFileEx, @function
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
.type DbgNtCancelSynchronousIoFile, @function
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
.type DbgNtCancelTimer2, @function
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
.type DbgNtCancelWaitCompletionPacket, @function
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
.type DbgNtCommitComplete, @function
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
.type DbgNtCommitEnlistment, @function
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
.type DbgNtCommitRegistryTransaction, @function
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
.type DbgNtCommitTransaction, @function
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
.type DbgNtCompactKeys, @function
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
.type DbgNtCompareObjects, @function
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
.type DbgNtCompareSigningLevels, @function
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
.type DbgNtCompareTokens, @function
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
.type DbgNtCompleteConnectPort, @function
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
.type DbgNtCompressKey, @function
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
.type DbgNtConnectPort, @function
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
.type DbgNtConvertBetweenAuxiliaryCounterAndPerformanceCounter, @function
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
.type DbgNtCreateDebugObject, @function
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
.type DbgNtCreateDirectoryObject, @function
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
.type DbgNtCreateDirectoryObjectEx, @function
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
.type DbgNtCreateEnclave, @function
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
.type DbgNtCreateEnlistment, @function
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
.type DbgNtCreateEventPair, @function
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
.type DbgNtCreateIRTimer, @function
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
.type DbgNtCreateIoCompletion, @function
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
.type DbgNtCreateJobObject, @function
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
.type DbgNtCreateJobSet, @function
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
.type DbgNtCreateKeyTransacted, @function
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
.type DbgNtCreateKeyedEvent, @function
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
.type DbgNtCreateLowBoxToken, @function
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
.type DbgNtCreateMailslotFile, @function
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
.type DbgNtCreateMutant, @function
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
.type DbgNtCreateNamedPipeFile, @function
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
.type DbgNtCreatePagingFile, @function
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
.type DbgNtCreatePartition, @function
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
.type DbgNtCreatePort, @function
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
.type DbgNtCreatePrivateNamespace, @function
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
.type DbgNtCreateProcess, @function
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
.type DbgNtCreateProfile, @function
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
.type DbgNtCreateProfileEx, @function
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
.type DbgNtCreateRegistryTransaction, @function
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
.type DbgNtCreateResourceManager, @function
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
.type DbgNtCreateSemaphore, @function
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
.type DbgNtCreateSymbolicLinkObject, @function
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
.type DbgNtCreateThreadEx, @function
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
.type DbgNtCreateTimer, @function
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
.type DbgNtCreateTimer2, @function
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
.type DbgNtCreateToken, @function
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
.type DbgNtCreateTokenEx, @function
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
.type DbgNtCreateTransaction, @function
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
.type DbgNtCreateTransactionManager, @function
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
.type DbgNtCreateUserProcess, @function
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
.type DbgNtCreateWaitCompletionPacket, @function
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
.type DbgNtCreateWaitablePort, @function
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
.type DbgNtCreateWnfStateName, @function
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
.type DbgNtCreateWorkerFactory, @function
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
.type DbgNtDebugActiveProcess, @function
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
.type DbgNtDebugContinue, @function
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
.type DbgNtDeleteAtom, @function
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
.type DbgNtDeleteBootEntry, @function
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
.type DbgNtDeleteDriverEntry, @function
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
.type DbgNtDeleteFile, @function
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
.type DbgNtDeleteKey, @function
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
.type DbgNtDeleteObjectAuditAlarm, @function
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
.type DbgNtDeletePrivateNamespace, @function
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
.type DbgNtDeleteValueKey, @function
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
.type DbgNtDeleteWnfStateData, @function
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
.type DbgNtDeleteWnfStateName, @function
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
.type DbgNtDisableLastKnownGood, @function
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
.type DbgNtDisplayString, @function
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
.type DbgNtDrawText, @function
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
.type DbgNtEnableLastKnownGood, @function
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
.type DbgNtEnumerateBootEntries, @function
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
.type DbgNtEnumerateDriverEntries, @function
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
.type DbgNtEnumerateSystemEnvironmentValuesEx, @function
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
.type DbgNtEnumerateTransactionObject, @function
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
.type DbgNtExtendSection, @function
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
.type DbgNtFilterBootOption, @function
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
.type DbgNtFilterToken, @function
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
.type DbgNtFilterTokenEx, @function
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
.type DbgNtFlushBuffersFileEx, @function
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
.type DbgNtFlushInstallUILanguage, @function
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
.type DbgNtFlushInstructionCache, @function
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
.type DbgNtFlushKey, @function
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
.type DbgNtFlushProcessWriteBuffers, @function
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
.type DbgNtFlushVirtualMemory, @function
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
.type DbgNtFlushWriteBuffer, @function
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
.type DbgNtFreeUserPhysicalPages, @function
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
.type DbgNtFreezeRegistry, @function
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
.type DbgNtFreezeTransactions, @function
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
.type DbgNtGetCachedSigningLevel, @function
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
.type DbgNtGetCompleteWnfStateSubscription, @function
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
.type DbgNtGetContextThread, @function
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
.type DbgNtGetCurrentProcessorNumber, @function
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
.type DbgNtGetCurrentProcessorNumberEx, @function
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
.type DbgNtGetDevicePowerState, @function
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
.type DbgNtGetMUIRegistryInfo, @function
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
.type DbgNtGetNextProcess, @function
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
.type DbgNtGetNextThread, @function
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
.type DbgNtGetNlsSectionPtr, @function
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
.type DbgNtGetNotificationResourceManager, @function
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
.type DbgNtGetWriteWatch, @function
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
.type DbgNtImpersonateAnonymousToken, @function
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
.type DbgNtImpersonateThread, @function
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
.type DbgNtInitializeEnclave, @function
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
.type DbgNtInitializeNlsFiles, @function
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
.type DbgNtInitializeRegistry, @function
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
.type DbgNtInitiatePowerAction, @function
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
.type DbgNtIsSystemResumeAutomatic, @function
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
.type DbgNtIsUILanguageComitted, @function
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
.type DbgNtListenPort, @function
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
.type DbgNtLoadDriver, @function
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
.type DbgNtLoadEnclaveData, @function
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
.type DbgNtLoadHotPatch, @function
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
.type DbgNtLoadKey, @function
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
.type DbgNtLoadKey2, @function
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
.type DbgNtLoadKeyEx, @function
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
.type DbgNtLockFile, @function
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
.type DbgNtLockProductActivationKeys, @function
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
.type DbgNtLockRegistryKey, @function
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
.type DbgNtLockVirtualMemory, @function
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
.type DbgNtMakePermanentObject, @function
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
.type DbgNtMakeTemporaryObject, @function
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
.type DbgNtManagePartition, @function
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
.type DbgNtMapCMFModule, @function
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
.type DbgNtMapUserPhysicalPages, @function
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
.type DbgNtMapViewOfSectionEx, @function
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
.type DbgNtModifyBootEntry, @function
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
.type DbgNtModifyDriverEntry, @function
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
.type DbgNtNotifyChangeDirectoryFile, @function
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
.type DbgNtNotifyChangeDirectoryFileEx, @function
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
.type DbgNtNotifyChangeKey, @function
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
.type DbgNtNotifyChangeMultipleKeys, @function
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
.type DbgNtNotifyChangeSession, @function
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
.type DbgNtOpenEnlistment, @function
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
.type DbgNtOpenEventPair, @function
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
.type DbgNtOpenIoCompletion, @function
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
.type DbgNtOpenJobObject, @function
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
.type DbgNtOpenKeyEx, @function
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
.type DbgNtOpenKeyTransacted, @function
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
.type DbgNtOpenKeyTransactedEx, @function
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
.type DbgNtOpenKeyedEvent, @function
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
.type DbgNtOpenMutant, @function
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
.type DbgNtOpenObjectAuditAlarm, @function
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
.type DbgNtOpenPartition, @function
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
.type DbgNtOpenPrivateNamespace, @function
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
.type DbgNtOpenProcessToken, @function
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
.type DbgNtOpenRegistryTransaction, @function
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
.type DbgNtOpenResourceManager, @function
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
.type DbgNtOpenSemaphore, @function
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
.type DbgNtOpenSession, @function
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
.type DbgNtOpenSymbolicLinkObject, @function
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
.type DbgNtOpenThread, @function
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
.type DbgNtOpenTimer, @function
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
.type DbgNtOpenTransaction, @function
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
.type DbgNtOpenTransactionManager, @function
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
.type DbgNtPlugPlayControl, @function
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
.type DbgNtPrePrepareComplete, @function
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
.type DbgNtPrePrepareEnlistment, @function
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
.type DbgNtPrepareComplete, @function
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
.type DbgNtPrepareEnlistment, @function
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
.type DbgNtPrivilegeCheck, @function
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
.type DbgNtPrivilegeObjectAuditAlarm, @function
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
.type DbgNtPrivilegedServiceAuditAlarm, @function
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
.type DbgNtPropagationComplete, @function
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
.type DbgNtPropagationFailed, @function
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
.type DbgNtPulseEvent, @function
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
.type DbgNtQueryAuxiliaryCounterFrequency, @function
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
.type DbgNtQueryBootEntryOrder, @function
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
.type DbgNtQueryBootOptions, @function
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
.type DbgNtQueryDebugFilterState, @function
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
.type DbgNtQueryDirectoryFileEx, @function
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
.type DbgNtQueryDirectoryObject, @function
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
.type DbgNtQueryDriverEntryOrder, @function
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
.type DbgNtQueryEaFile, @function
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
.type DbgNtQueryFullAttributesFile, @function
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
.type DbgNtQueryInformationAtom, @function
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
.type DbgNtQueryInformationByName, @function
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
.type DbgNtQueryInformationEnlistment, @function
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
.type DbgNtQueryInformationJobObject, @function
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
.type DbgNtQueryInformationPort, @function
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
.type DbgNtQueryInformationResourceManager, @function
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
.type DbgNtQueryInformationTransaction, @function
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
.type DbgNtQueryInformationTransactionManager, @function
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
.type DbgNtQueryInformationWorkerFactory, @function
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
.type DbgNtQueryInstallUILanguage, @function
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
.type DbgNtQueryIntervalProfile, @function
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
.type DbgNtQueryIoCompletion, @function
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
.type DbgNtQueryLicenseValue, @function
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
.type DbgNtQueryMultipleValueKey, @function
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
.type DbgNtQueryMutant, @function
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
.type DbgNtQueryOpenSubKeys, @function
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
.type DbgNtQueryOpenSubKeysEx, @function
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
.type DbgNtQueryPortInformationProcess, @function
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
.type DbgNtQueryQuotaInformationFile, @function
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
.type DbgNtQuerySecurityAttributesToken, @function
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
.type DbgNtQuerySecurityObject, @function
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
.type DbgNtQuerySecurityPolicy, @function
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
.type DbgNtQuerySemaphore, @function
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
.type DbgNtQuerySymbolicLinkObject, @function
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
.type DbgNtQuerySystemEnvironmentValue, @function
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
.type DbgNtQuerySystemEnvironmentValueEx, @function
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
.type DbgNtQuerySystemInformationEx, @function
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
.type DbgNtQueryTimerResolution, @function
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
.type DbgNtQueryWnfStateData, @function
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
.type DbgNtQueryWnfStateNameInformation, @function
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
.type DbgNtQueueApcThreadEx, @function
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
.type DbgNtRaiseException, @function
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
.type DbgNtRaiseHardError, @function
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
.type DbgNtReadOnlyEnlistment, @function
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
.type DbgNtRecoverEnlistment, @function
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
.type DbgNtRecoverResourceManager, @function
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
.type DbgNtRecoverTransactionManager, @function
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
.type DbgNtRegisterProtocolAddressInformation, @function
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
.type DbgNtRegisterThreadTerminatePort, @function
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
.type DbgNtReleaseKeyedEvent, @function
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
.type DbgNtReleaseWorkerFactoryWorker, @function
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
.type DbgNtRemoveIoCompletionEx, @function
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
.type DbgNtRemoveProcessDebug, @function
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
.type DbgNtRenameKey, @function
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
.type DbgNtRenameTransactionManager, @function
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
.type DbgNtReplaceKey, @function
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
.type DbgNtReplacePartitionUnit, @function
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
.type DbgNtReplyWaitReplyPort, @function
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
.type DbgNtRequestPort, @function
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
.type DbgNtResetEvent, @function
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
.type DbgNtResetWriteWatch, @function
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
.type DbgNtRestoreKey, @function
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
.type DbgNtResumeProcess, @function
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
.type DbgNtRevertContainerImpersonation, @function
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
.type DbgNtRollbackComplete, @function
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
.type DbgNtRollbackEnlistment, @function
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
.type DbgNtRollbackRegistryTransaction, @function
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
.type DbgNtRollbackTransaction, @function
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
.type DbgNtRollforwardTransactionManager, @function
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
.type DbgNtSaveKey, @function
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
.type DbgNtSaveKeyEx, @function
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
.type DbgNtSaveMergedKeys, @function
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
.type DbgNtSecureConnectPort, @function
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
.type DbgNtSerializeBoot, @function
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
.type DbgNtSetBootEntryOrder, @function
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
.type DbgNtSetBootOptions, @function
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
.type DbgNtSetCachedSigningLevel, @function
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
.type DbgNtSetCachedSigningLevel2, @function
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
.type DbgNtSetContextThread, @function
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
.type DbgNtSetDebugFilterState, @function
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
.type DbgNtSetDefaultHardErrorPort, @function
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
.type DbgNtSetDefaultLocale, @function
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
.type DbgNtSetDefaultUILanguage, @function
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
.type DbgNtSetDriverEntryOrder, @function
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
.type DbgNtSetEaFile, @function
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
.type DbgNtSetHighEventPair, @function
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
.type DbgNtSetHighWaitLowEventPair, @function
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
.type DbgNtSetIRTimer, @function
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
.type DbgNtSetInformationDebugObject, @function
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
.type DbgNtSetInformationEnlistment, @function
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
.type DbgNtSetInformationJobObject, @function
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
.type DbgNtSetInformationKey, @function
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
.type DbgNtSetInformationResourceManager, @function
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
.type DbgNtSetInformationSymbolicLink, @function
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
.type DbgNtSetInformationToken, @function
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
.type DbgNtSetInformationTransaction, @function
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
.type DbgNtSetInformationTransactionManager, @function
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
.type DbgNtSetInformationVirtualMemory, @function
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
.type DbgNtSetInformationWorkerFactory, @function
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
.type DbgNtSetIntervalProfile, @function
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
.type DbgNtSetIoCompletion, @function
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
.type DbgNtSetIoCompletionEx, @function
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
.type DbgNtSetLdtEntries, @function
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
.type DbgNtSetLowEventPair, @function
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
.type DbgNtSetLowWaitHighEventPair, @function
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
.type DbgNtSetQuotaInformationFile, @function
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
.type DbgNtSetSecurityObject, @function
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
.type DbgNtSetSystemEnvironmentValue, @function
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
.type DbgNtSetSystemEnvironmentValueEx, @function
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
.type DbgNtSetSystemInformation, @function
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
.type DbgNtSetSystemPowerState, @function
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
.type DbgNtSetSystemTime, @function
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
.type DbgNtSetThreadExecutionState, @function
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
.type DbgNtSetTimer2, @function
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
.type DbgNtSetTimerEx, @function
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
.type DbgNtSetTimerResolution, @function
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
.type DbgNtSetUuidSeed, @function
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
.type DbgNtSetVolumeInformationFile, @function
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
.type DbgNtSetWnfProcessNotificationEvent, @function
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
.type DbgNtShutdownSystem, @function
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
.type DbgNtShutdownWorkerFactory, @function
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
.type DbgNtSignalAndWaitForSingleObject, @function
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
.type DbgNtSinglePhaseReject, @function
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
.type DbgNtStartProfile, @function
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
.type DbgNtStopProfile, @function
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
.type DbgNtSubscribeWnfStateChange, @function
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
.type DbgNtSuspendProcess, @function
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
.type DbgNtSuspendThread, @function
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
.type DbgNtSystemDebugControl, @function
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
.type DbgNtTerminateEnclave, @function
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
.type DbgNtTerminateJobObject, @function
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
.type DbgNtTestAlert, @function
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
.type DbgNtThawRegistry, @function
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
.type DbgNtThawTransactions, @function
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
.type DbgNtTraceControl, @function
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
.type DbgNtTranslateFilePath, @function
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
.type DbgNtUmsThreadYield, @function
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
.type DbgNtUnloadDriver, @function
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
.type DbgNtUnloadKey, @function
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
.type DbgNtUnloadKey2, @function
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
.type DbgNtUnloadKeyEx, @function
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
.type DbgNtUnlockFile, @function
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
.type DbgNtUnlockVirtualMemory, @function
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
.type DbgNtUnmapViewOfSectionEx, @function
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
.type DbgNtUnsubscribeWnfStateChange, @function
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
.type DbgNtUpdateWnfStateData, @function
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
.type DbgNtVdmControl, @function
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
.type DbgNtWaitForAlertByThreadId, @function
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
.type DbgNtWaitForDebugEvent, @function
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
.type DbgNtWaitForKeyedEvent, @function
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
.type DbgNtWaitForWorkViaWorkerFactory, @function
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
.type DbgNtWaitHighEventPair, @function
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
.type DbgNtWaitLowEventPair, @function
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
.type DbgNtAcquireCMFViewOwnership, @function
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
.type DbgNtCancelDeviceWakeupRequest, @function
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
.type DbgNtClearAllSavepointsTransaction, @function
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
.type DbgNtClearSavepointTransaction, @function
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
.type DbgNtRollbackSavepointTransaction, @function
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
.type DbgNtSavepointTransaction, @function
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
.type DbgNtSavepointComplete, @function
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
.type DbgNtCreateSectionEx, @function
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
.type DbgNtCreateCrossVmEvent, @function
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
.type DbgNtListTransactions, @function
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
.type DbgNtMarshallTransaction, @function
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
.type DbgNtPullTransaction, @function
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
.type DbgNtReleaseCMFViewOwnership, @function
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
.type DbgNtWaitForWnfNotifications, @function
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
.type DbgNtStartTm, @function
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
.type DbgNtSetInformationProcess, @function
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
.type DbgNtRequestDeviceWakeup, @function
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
.type DbgNtRequestWakeupLatency, @function
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
.type DbgNtQuerySystemTime, @function
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
.type DbgNtManageHotPatch, @function
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
.type DbgNtContinueEx, @function
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
