#include "syscall.h"

#ifndef SYSCALL_DEFINE
#error "Include syscall.h instead of syscalls.h directly"
#endif

SYSCALL_DEFINE(AccessCheck,
    NTSTATUS,
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    HANDLE ClientToken,
    ACCESS_MASK DesiaredAccess,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PBOOLEAN AccessStatus
)

SYSCALL_DEFINE(WorkerFactoryWorkerReady,
    NTSTATUS,
    HANDLE WorkerFactoryHandle
)

SYSCALL_DEFINE(AcceptConnectPort,
    NTSTATUS,
    PHANDLE ServerPortHandle,
    ULONG AlternativeReceivePortHandle,
    PPORT_MESSAGE ConnectionReply,
    BOOLEAN AcceptConnection,
    PPORT_SECTION_WRITE ServerSharedMemory,
    PPORT_SECTION_READ ClientSharedMemory
)

SYSCALL_DEFINE(MapUserPhysicalPagesScatter,
    NTSTATUS,
    PVOID VirtualAddresses,
    PULONG NumberOfPages,
    PULONG UserPfnArray
)

SYSCALL_DEFINE(WaitForSingleObject,
    NTSTATUS,
    HANDLE ObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER TimeOut
)

SYSCALL_DEFINE(CallbackReturn,
    NTSTATUS,
    PVOID OutputBuffer,
    ULONG OutputLength,
    NTSTATUS Status
)

SYSCALL_DEFINE(ReadFile,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
)

SYSCALL_DEFINE(DeviceIoControlFile,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
)

SYSCALL_DEFINE(WriteFile,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
)

SYSCALL_DEFINE(RemoveIoCompletion,
    NTSTATUS,
    HANDLE IoCompletionHandle,
    PULONG KeyContext,
    PULONG ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(ReleaseSemaphore,
    NTSTATUS,
    HANDLE SemaphoreHandle,
    LONG ReleaseCount,
    PLONG PreviousCount
)

SYSCALL_DEFINE(ReplyWaitReceivePort,
    NTSTATUS,
    HANDLE PortHandle,
    PVOID PortContext,
    PPORT_MESSAGE ReplyMessage,
    PPORT_MESSAGE ReceiveMessage
)

SYSCALL_DEFINE(ReplyPort,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage
)

SYSCALL_DEFINE(SetInformationThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
)

SYSCALL_DEFINE(SetEvent,
    NTSTATUS,
    HANDLE EventHandle,
    PULONG PreviousState
)

SYSCALL_DEFINE(Close,
    NTSTATUS,
    HANDLE Handle
)

SYSCALL_DEFINE(QueryObject,
    NTSTATUS,
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInformationFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
)

SYSCALL_DEFINE(OpenKey,
    NTSTATUS,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(EnumerateValueKey,
    NTSTATUS,
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
)

SYSCALL_DEFINE(FindAtom,
    NTSTATUS,
    PWSTR AtomName,
    ULONG Length,
    PUSHORT Atom
)

SYSCALL_DEFINE(QueryDefaultLocale,
    NTSTATUS,
    BOOLEAN UserProfile,
    PLCID DefaultLocaleId
)

SYSCALL_DEFINE(QueryKey,
    NTSTATUS,
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
)

SYSCALL_DEFINE(QueryValueKey,
    NTSTATUS,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
)

SYSCALL_DEFINE(AllocateVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
)

SYSCALL_DEFINE(QueryInformationProcess,
    NTSTATUS,
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(WaitForMultipleObjects32,
    NTSTATUS,
    ULONG ObjectCount,
    PHANDLE Handles,
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(WriteFileGather,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_SEGMENT_ELEMENT SegmentArray,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
)

SYSCALL_DEFINE(CreateKey,
    NTSTATUS,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
)

SYSCALL_DEFINE(FreeVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
)

SYSCALL_DEFINE(ImpersonateClientOfPort,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE Message
)

SYSCALL_DEFINE(ReleaseMutant,
    NTSTATUS,
    HANDLE MutantHandle,
    PULONG PreviousCount
)

SYSCALL_DEFINE(QueryInformationToken,
    NTSTATUS,
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(RequestWaitReplyPort,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage
)

SYSCALL_DEFINE(QueryVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
)

SYSCALL_DEFINE(OpenThreadToken,
    NTSTATUS,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle
)

SYSCALL_DEFINE(QueryInformationThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(OpenProcess,
    NTSTATUS,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
)

SYSCALL_DEFINE(SetInformationFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
)

SYSCALL_DEFINE(MapViewOfSection,
    NTSTATUS,
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
)

SYSCALL_DEFINE(AccessCheckAndAuditAlarm,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PVOID HandleId,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping,
    BOOLEAN ObjectCreation,
    PACCESS_MASK GrantedAccess,
    PBOOLEAN AccessStatus,
    PBOOLEAN GenerateOnClose
)

SYSCALL_DEFINE(UnmapViewOfSection,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress
)

SYSCALL_DEFINE(ReplyWaitReceivePortEx,
    NTSTATUS,
    HANDLE PortHandle,
    PULONG PortContext,
    PPORT_MESSAGE ReplyMessage,
    PPORT_MESSAGE ReceiveMessage,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(TerminateProcess,
    NTSTATUS,
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
)

SYSCALL_DEFINE(SetEventBoostPriority,
    NTSTATUS,
    HANDLE EventHandle
)

SYSCALL_DEFINE(ReadFileScatter,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_SEGMENT_ELEMENT SegmentArray,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
)

SYSCALL_DEFINE(OpenThreadTokenEx,
    NTSTATUS,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    ULONG HandleAttributes,
    PHANDLE TokenHandle
)

SYSCALL_DEFINE(OpenProcessTokenEx,
    NTSTATUS,
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    PHANDLE TokenHandle
)

SYSCALL_DEFINE(QueryPerformanceCounter,
    NTSTATUS,
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency
)

SYSCALL_DEFINE(EnumerateKey,
    NTSTATUS,
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
)

SYSCALL_DEFINE(OpenFile,
    NTSTATUS,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
)

SYSCALL_DEFINE(DelayExecution,
    NTSTATUS,
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
)

SYSCALL_DEFINE(QueryDirectoryFile,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
)

SYSCALL_DEFINE(QuerySystemInformation,
    NTSTATUS,
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(OpenSection,
    NTSTATUS,
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(QueryTimer,
    NTSTATUS,
    HANDLE TimerHandle,
    TIMER_INFORMATION_CLASS TimerInformationClass,
    PVOID TimerInformation,
    ULONG TimerInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(FsControlFile,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
)

SYSCALL_DEFINE(WriteVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
)

SYSCALL_DEFINE(CloseObjectAuditAlarm,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PVOID HandleId,
    BOOLEAN GenerateOnClose
)

SYSCALL_DEFINE(DuplicateObject,
    NTSTATUS,
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
)

SYSCALL_DEFINE(QueryAttributesFile,
    NTSTATUS,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
)

SYSCALL_DEFINE(ClearEvent,
    NTSTATUS,
    HANDLE EventHandle
)

SYSCALL_DEFINE(ReadVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
)

SYSCALL_DEFINE(OpenEvent,
    NTSTATUS,
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(AdjustPrivilegesToken,
    NTSTATUS,
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PULONG ReturnLength
)

SYSCALL_DEFINE(DuplicateToken,
    NTSTATUS,
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE TokenType,
    PHANDLE NewTokenHandle
)

SYSCALL_DEFINE(Continue,
    NTSTATUS,
    PCONTEXT ContextRecord,
    BOOLEAN TestAlert
)

SYSCALL_DEFINE(QueryDefaultUILanguage,
    NTSTATUS,
    PLANGID DefaultUILanguageId
)

SYSCALL_DEFINE(QueueApcThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
)

SYSCALL_DEFINE(YieldExecution,
    NTSTATUS
)

SYSCALL_DEFINE(AddAtom,
    NTSTATUS,
    PWSTR AtomName,
    ULONG Length,
    PUSHORT Atom
)

SYSCALL_DEFINE(CreateEvent,
    NTSTATUS,
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    EVENT_TYPE EventType,
    BOOLEAN InitialState
)

SYSCALL_DEFINE(QueryVolumeInformationFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FSINFOCLASS FsInformationClass
)

SYSCALL_DEFINE(CreateSection,
    NTSTATUS,
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
)

SYSCALL_DEFINE(FlushBuffersFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
)

SYSCALL_DEFINE(ApphelpCacheControl,
    NTSTATUS,
    APPHELPCACHESERVICECLASS Service,
    PVOID ServiceData
)

SYSCALL_DEFINE(CreateProcessEx,
    NTSTATUS,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    ULONG JobMemberLevel
)

SYSCALL_DEFINE(CreateThread,
    NTSTATUS,
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PUSER_STACK InitialTeb,
    BOOLEAN CreateSuspended
)

SYSCALL_DEFINE(IsProcessInJob,
    NTSTATUS,
    HANDLE ProcessHandle,
    HANDLE JobHandle
)

SYSCALL_DEFINE(ProtectVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
)

SYSCALL_DEFINE(QuerySection,
    NTSTATUS,
    HANDLE SectionHandle,
    SECTION_INFORMATION_CLASS SectionInformationClass,
    PVOID SectionInformation,
    ULONG SectionInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(ResumeThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
)

SYSCALL_DEFINE(TerminateThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus
)

SYSCALL_DEFINE(ReadRequestData,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesRead
)

SYSCALL_DEFINE(CreateFile,
    NTSTATUS,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
)

SYSCALL_DEFINE(QueryEvent,
    NTSTATUS,
    HANDLE EventHandle,
    EVENT_INFORMATION_CLASS EventInformationClass,
    PVOID EventInformation,
    ULONG EventInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(WriteRequestData,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE Request,
    ULONG DataIndex,
    PVOID Buffer,
    ULONG Length,
    PULONG ResultLength
)

SYSCALL_DEFINE(OpenDirectoryObject,
    NTSTATUS,
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(AccessCheckByTypeAndAuditAlarm,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PVOID HandleId,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid,
    ACCESS_MASK DesiredAccess,
    AUDIT_EVENT_TYPE AuditType,
    ULONG Flags,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    BOOLEAN ObjectCreation,
    PACCESS_MASK GrantedAccess,
    PULONG AccessStatus,
    PBOOLEAN GenerateOnClose
)

SYSCALL_DEFINE(WaitForMultipleObjects,
    NTSTATUS,
    ULONG Count,
    PHANDLE Handles,
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(SetInformationObject,
    NTSTATUS,
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength
)

SYSCALL_DEFINE(CancelIoFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
)

SYSCALL_DEFINE(TraceEvent,
    NTSTATUS,
    HANDLE TraceHandle,
    ULONG Flags,
    ULONG FieldSize,
    PVOID Fields
)

SYSCALL_DEFINE(PowerInformation,
    NTSTATUS,
    POWER_INFORMATION_LEVEL InformationLevel,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
)

SYSCALL_DEFINE(SetValueKey,
    NTSTATUS,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID SystemData,
    ULONG DataSize
)

SYSCALL_DEFINE(CancelTimer,
    NTSTATUS,
    HANDLE TimerHandle,
    PBOOLEAN CurrentState
)

SYSCALL_DEFINE(SetTimer,
    NTSTATUS,
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PTIMER_APC_ROUTINE TimerApcRoutine,
    PVOID TimerContext,
    BOOLEAN ResumeTimer,
    LONG Period,
    PBOOLEAN PreviousState
)

SYSCALL_DEFINE(AccessCheckByType,
    NTSTATUS,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid,
    HANDLE ClientToken,
    ULONG DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PULONG AccessStatus
)

SYSCALL_DEFINE(AccessCheckByTypeResultList,
    NTSTATUS,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PULONG AccessStatus
)

SYSCALL_DEFINE(AccessCheckByTypeResultListAndAuditAlarm,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PVOID HandleId,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid,
    ACCESS_MASK DesiredAccess,
    AUDIT_EVENT_TYPE AuditType,
    ULONG Flags,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    BOOLEAN ObjectCreation,
    PACCESS_MASK GrantedAccess,
    PULONG AccessStatus,
    PULONG GenerateOnClose
)

SYSCALL_DEFINE(AccessCheckByTypeResultListAndAuditAlarmByHandle,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PVOID HandleId,
    HANDLE ClientToken,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid,
    ACCESS_MASK DesiredAccess,
    AUDIT_EVENT_TYPE AuditType,
    ULONG Flags,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    BOOLEAN ObjectCreation,
    PACCESS_MASK GrantedAccess,
    PULONG AccessStatus,
    PULONG GenerateOnClose
)

SYSCALL_DEFINE(AcquireProcessActivityReference,
    NTSTATUS
)

SYSCALL_DEFINE(AddAtomEx,
    NTSTATUS,
    PWSTR AtomName,
    ULONG Length,
    PRTL_ATOM Atom,
    ULONG Flags
)

SYSCALL_DEFINE(AddBootEntry,
    NTSTATUS,
    PBOOT_ENTRY BootEntry,
    PULONG Id
)

SYSCALL_DEFINE(AddDriverEntry,
    NTSTATUS,
    PEFI_DRIVER_ENTRY DriverEntry,
    PULONG Id
)

SYSCALL_DEFINE(AdjustGroupsToken,
    NTSTATUS,
    HANDLE TokenHandle,
    BOOLEAN ResetToDefault,
    PTOKEN_GROUPS NewState,
    ULONG BufferLength,
    PTOKEN_GROUPS PreviousState,
    PULONG ReturnLength
)

SYSCALL_DEFINE(AdjustTokenClaimsAndDeviceGroups,
    NTSTATUS,
    HANDLE TokenHandle,
    BOOLEAN UserResetToDefault,
    BOOLEAN DeviceResetToDefault,
    BOOLEAN DeviceGroupsResetToDefault,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState,
    PTOKEN_GROUPS NewDeviceGroupsState,
    ULONG UserBufferLength,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState,
    ULONG DeviceBufferLength,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState,
    ULONG DeviceGroupsBufferLength,
    PTOKEN_GROUPS PreviousDeviceGroups,
    PULONG UserReturnLength,
    PULONG DeviceReturnLength,
    PULONG DeviceGroupsReturnBufferLength
)

SYSCALL_DEFINE(AlertResumeThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
)

SYSCALL_DEFINE(AlertThread,
    NTSTATUS,
    HANDLE ThreadHandle
)

SYSCALL_DEFINE(AlertThreadByThreadId,
    NTSTATUS,
    ULONG ThreadId
)

SYSCALL_DEFINE(AllocateLocallyUniqueId,
    NTSTATUS,
    PLUID Luid
)

SYSCALL_DEFINE(AllocateReserveObject,
    NTSTATUS,
    PHANDLE MemoryReserveHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    MEMORY_RESERVE_TYPE Type
)

SYSCALL_DEFINE(AllocateUserPhysicalPages,
    NTSTATUS,
    HANDLE ProcessHandle,
    PULONG NumberOfPages,
    PULONG UserPfnArray
)

SYSCALL_DEFINE(AllocateUuids,
    NTSTATUS,
    PLARGE_INTEGER Time,
    PULONG Range,
    PULONG Sequence,
    PUCHAR Seed
)

SYSCALL_DEFINE(AllocateVirtualMemoryEx,
    NTSTATUS,
    HANDLE ProcessHandle,
    PPVOID lpAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T pSize,
    ULONG flAllocationType,
    PVOID DataBuffer,
    ULONG DataCount
)

SYSCALL_DEFINE(AlpcAcceptConnectPort,
    NTSTATUS,
    PHANDLE PortHandle,
    HANDLE ConnectionPortHandle,
    ULONG Flags,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes,
    PVOID PortContext,
    PPORT_MESSAGE ConnectionRequest,
    PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    BOOLEAN AcceptConnection
)

SYSCALL_DEFINE(AlpcCancelMessage,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_CONTEXT_ATTR MessageContext
)

SYSCALL_DEFINE(AlpcConnectPort,
    NTSTATUS,
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes,
    ULONG Flags,
    PSID RequiredServerSid,
    PPORT_MESSAGE ConnectionMessage,
    PULONG BufferLength,
    PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(AlpcConnectPortEx,
    NTSTATUS,
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
    POBJECT_ATTRIBUTES ClientPortObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes,
    ULONG Flags,
    PSECURITY_DESCRIPTOR ServerSecurityRequirements,
    PPORT_MESSAGE ConnectionMessage,
    PSIZE_T BufferLength,
    PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(AlpcCreatePort,
    NTSTATUS,
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes
)

SYSCALL_DEFINE(AlpcCreatePortSection,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    HANDLE SectionHandle,
    SIZE_T SectionSize,
    PHANDLE AlpcSectionHandle,
    PSIZE_T ActualSectionSize
)

SYSCALL_DEFINE(AlpcCreateResourceReserve,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    SIZE_T MessageSize,
    PHANDLE ResourceId
)

SYSCALL_DEFINE(AlpcCreateSectionView,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_DATA_VIEW_ATTR ViewAttributes
)

SYSCALL_DEFINE(AlpcCreateSecurityContext,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    PALPC_SECURITY_ATTR SecurityAttribute
)

SYSCALL_DEFINE(AlpcDeletePortSection,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    HANDLE SectionHandle
)

SYSCALL_DEFINE(AlpcDeleteResourceReserve,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    HANDLE ResourceId
)

SYSCALL_DEFINE(AlpcDeleteSectionView,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    PVOID ViewBase
)

SYSCALL_DEFINE(AlpcDeleteSecurityContext,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    HANDLE ContextHandle
)

SYSCALL_DEFINE(AlpcDisconnectPort,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags
)

SYSCALL_DEFINE(AlpcImpersonateClientContainerOfPort,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG Flags
)

SYSCALL_DEFINE(AlpcImpersonateClientOfPort,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    PVOID Flags
)

SYSCALL_DEFINE(AlpcOpenSenderProcess,
    NTSTATUS,
    PHANDLE ProcessHandle,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ULONG Flags,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(AlpcOpenSenderThread,
    NTSTATUS,
    PHANDLE ThreadHandle,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ULONG Flags,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(AlpcQueryInformation,
    NTSTATUS,
    HANDLE PortHandle,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length,
    PULONG ReturnLength
)

SYSCALL_DEFINE(AlpcQueryInformationMessage,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE PortMessage,
    ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
    PVOID MessageInformation,
    ULONG Length,
    PULONG ReturnLength
)

SYSCALL_DEFINE(AlpcRevokeSecurityContext,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    HANDLE ContextHandle
)

SYSCALL_DEFINE(AlpcSendWaitReceivePort,
    NTSTATUS,
    HANDLE PortHandle,
    ULONG Flags,
    PPORT_MESSAGE SendMessage,
    PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    PPORT_MESSAGE ReceiveMessage,
    PSIZE_T BufferLength,
    PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(AlpcSetInformation,
    NTSTATUS,
    HANDLE PortHandle,
    ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length
)

SYSCALL_DEFINE(AreMappedFilesTheSame,
    NTSTATUS,
    PVOID File1MappedAsAnImage,
    PVOID File2MappedAsFile
)

SYSCALL_DEFINE(AssignProcessToJobObject,
    NTSTATUS,
    HANDLE JobHandle,
    HANDLE ProcessHandle
)

SYSCALL_DEFINE(AssociateWaitCompletionPacket,
    NTSTATUS,
    HANDLE WaitCompletionPacketHandle,
    HANDLE IoCompletionHandle,
    HANDLE TargetObjectHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation,
    PBOOLEAN AlreadySignaled
)

SYSCALL_DEFINE(CallEnclave,
    NTSTATUS,
    PENCLAVE_ROUTINE Routine,
    PVOID Parameter,
    BOOLEAN WaitForThread,
    PVOID ReturnValue
)

SYSCALL_DEFINE(CancelIoFileEx,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoRequestToCancel,
    PIO_STATUS_BLOCK IoStatusBlock
)

SYSCALL_DEFINE(CancelSynchronousIoFile,
    NTSTATUS,
    HANDLE ThreadHandle,
    PIO_STATUS_BLOCK IoRequestToCancel,
    PIO_STATUS_BLOCK IoStatusBlock
)

SYSCALL_DEFINE(CancelTimer2,
    NTSTATUS,
    HANDLE TimerHandle,
    PT2_CANCEL_PARAMETERS Parameters
)

SYSCALL_DEFINE(CancelWaitCompletionPacket,
    NTSTATUS,
    HANDLE WaitCompletionPacketHandle,
    BOOLEAN RemoveSignaledPacket
)

SYSCALL_DEFINE(CommitComplete,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(CommitEnlistment,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(CommitRegistryTransaction,
    NTSTATUS,
    HANDLE RegistryHandle,
    BOOL Wait
)

SYSCALL_DEFINE(CommitTransaction,
    NTSTATUS,
    HANDLE TransactionHandle,
    BOOLEAN Wait
)

SYSCALL_DEFINE(CompactKeys,
    NTSTATUS,
    ULONG Count,
    HANDLE KeyArray
)

SYSCALL_DEFINE(CompareObjects,
    NTSTATUS,
    HANDLE FirstObjectHandle,
    HANDLE SecondObjectHandle
)

SYSCALL_DEFINE(CompareSigningLevels,
    NTSTATUS,
    ULONG UnknownParameter1,
    ULONG UnknownParameter2
)

SYSCALL_DEFINE(CompareTokens,
    NTSTATUS,
    HANDLE FirstTokenHandle,
    HANDLE SecondTokenHandle,
    PBOOLEAN Equal
)

SYSCALL_DEFINE(CompleteConnectPort,
    NTSTATUS,
    HANDLE PortHandle
)

SYSCALL_DEFINE(CompressKey,
    NTSTATUS,
    HANDLE Key
)

SYSCALL_DEFINE(ConnectPort,
    NTSTATUS,
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_SECTION_WRITE ClientView,
    PPORT_SECTION_READ ServerView,
    PULONG MaxMessageLength,
    PVOID ConnectionInformation,
    PULONG ConnectionInformationLength
)

SYSCALL_DEFINE(ConvertBetweenAuxiliaryCounterAndPerformanceCounter,
    NTSTATUS,
    ULONG UnknownParameter1,
    ULONG UnknownParameter2,
    ULONG UnknownParameter3,
    ULONG UnknownParameter4
)

SYSCALL_DEFINE(CreateDebugObject,
    NTSTATUS,
    PHANDLE DebugObjectHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Flags
)

SYSCALL_DEFINE(CreateDirectoryObject,
    NTSTATUS,
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(CreateDirectoryObjectEx,
    NTSTATUS,
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ShadowDirectoryHandle,
    ULONG Flags
)

SYSCALL_DEFINE(CreateEnclave,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T Size,
    SIZE_T InitialCommitment,
    ULONG EnclaveType,
    PVOID EnclaveInformation,
    ULONG EnclaveInformationLength,
    PULONG EnclaveError
)

SYSCALL_DEFINE(CreateEnlistment,
    NTSTATUS,
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    HANDLE TransactionHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG CreateOptions,
    NOTIFICATION_MASK NotificationMask,
    PVOID EnlistmentKey
)

SYSCALL_DEFINE(CreateEventPair,
    NTSTATUS,
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(CreateIRTimer,
    NTSTATUS,
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess
)

SYSCALL_DEFINE(CreateIoCompletion,
    NTSTATUS,
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Count
)

SYSCALL_DEFINE(CreateJobObject,
    NTSTATUS,
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(CreateJobSet,
    NTSTATUS,
    ULONG NumJob,
    PJOB_SET_ARRAY UserJobSet,
    ULONG Flags
)

SYSCALL_DEFINE(CreateKeyTransacted,
    NTSTATUS,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    HANDLE TransactionHandle,
    PULONG Disposition
)

SYSCALL_DEFINE(CreateKeyedEvent,
    NTSTATUS,
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Flags
)

SYSCALL_DEFINE(CreateLowBoxToken,
    NTSTATUS,
    PHANDLE TokenHandle,
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PSID PackageSid,
    ULONG CapabilityCount,
    PSID_AND_ATTRIBUTES Capabilities,
    ULONG HandleCount,
    HANDLE Handles
)

SYSCALL_DEFINE(CreateMailslotFile,
    NTSTATUS,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CreateOptions,
    ULONG MailslotQuota,
    ULONG MaximumMessageSize,
    PLARGE_INTEGER ReadTimeout
)

SYSCALL_DEFINE(CreateMutant,
    NTSTATUS,
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN InitialOwner
)

SYSCALL_DEFINE(CreateNamedPipeFile,
    NTSTATUS,
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    BOOLEAN NamedPipeType,
    BOOLEAN ReadMode,
    BOOLEAN CompletionMode,
    ULONG MaximumInstances,
    ULONG InboundQuota,
    ULONG OutboundQuota,
    PLARGE_INTEGER DefaultTimeout
)

SYSCALL_DEFINE(CreatePagingFile,
    NTSTATUS,
    PUNICODE_STRING PageFileName,
    PULARGE_INTEGER MinimumSize,
    PULARGE_INTEGER MaximumSize,
    ULONG Priority
)

SYSCALL_DEFINE(CreatePartition,
    NTSTATUS,
    PHANDLE PartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG PreferredNode
)

SYSCALL_DEFINE(CreatePort,
    NTSTATUS,
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage
)

SYSCALL_DEFINE(CreatePrivateNamespace,
    NTSTATUS,
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID BoundaryDescriptor
)

SYSCALL_DEFINE(CreateProcess,
    NTSTATUS,
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort
)

SYSCALL_DEFINE(CreateProfile,
    NTSTATUS,
    PHANDLE ProfileHandle,
    HANDLE Process,
    PVOID ProfileBase,
    ULONG ProfileSize,
    ULONG BucketSize,
    PULONG Buffer,
    ULONG BufferSize,
    KPROFILE_SOURCE ProfileSource,
    ULONG Affinity
)

SYSCALL_DEFINE(CreateProfileEx,
    NTSTATUS,
    PHANDLE ProfileHandle,
    HANDLE Process,
    PVOID ProfileBase,
    SIZE_T ProfileSize,
    ULONG BucketSize,
    PULONG Buffer,
    ULONG BufferSize,
    KPROFILE_SOURCE ProfileSource,
    USHORT GroupCount,
    PGROUP_AFFINITY GroupAffinity
)

SYSCALL_DEFINE(CreateRegistryTransaction,
    NTSTATUS,
    PHANDLE Handle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    DWORD Flags
)

SYSCALL_DEFINE(CreateResourceManager,
    NTSTATUS,
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID RmGuid,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG CreateOptions,
    PUNICODE_STRING Description
)

SYSCALL_DEFINE(CreateSemaphore,
    NTSTATUS,
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    LONG InitialCount,
    LONG MaximumCount
)

SYSCALL_DEFINE(CreateSymbolicLinkObject,
    NTSTATUS,
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LinkTarget
)

SYSCALL_DEFINE(CreateThreadEx,
    NTSTATUS,
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
)

SYSCALL_DEFINE(CreateTimer,
    NTSTATUS,
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TIMER_TYPE TimerType
)

SYSCALL_DEFINE(CreateTimer2,
    NTSTATUS,
    PHANDLE TimerHandle,
    PVOID Reserved1,
    PVOID Reserved2,
    ULONG Attributes,
    ACCESS_MASK DesiredAccess
)

SYSCALL_DEFINE(CreateToken,
    NTSTATUS,
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TOKEN_TYPE TokenType,
    PLUID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER User,
    PTOKEN_GROUPS Groups,
    PTOKEN_PRIVILEGES Privileges,
    PTOKEN_OWNER Owner,
    PTOKEN_PRIMARY_GROUP PrimaryGroup,
    PTOKEN_DEFAULT_DACL DefaultDacl,
    PTOKEN_SOURCE TokenSource
)

SYSCALL_DEFINE(CreateTokenEx,
    NTSTATUS,
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TOKEN_TYPE TokenType,
    PLUID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER User,
    PTOKEN_GROUPS Groups,
    PTOKEN_PRIVILEGES Privileges,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes,
    PTOKEN_GROUPS DeviceGroups,
    PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy,
    PTOKEN_OWNER Owner,
    PTOKEN_PRIMARY_GROUP PrimaryGroup,
    PTOKEN_DEFAULT_DACL DefaultDacl,
    PTOKEN_SOURCE TokenSource
)

SYSCALL_DEFINE(CreateTransaction,
    NTSTATUS,
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    LPGUID Uow,
    HANDLE TmHandle,
    ULONG CreateOptions,
    ULONG IsolationLevel,
    ULONG IsolationFlags,
    PLARGE_INTEGER Timeout,
    PUNICODE_STRING Description
)

SYSCALL_DEFINE(CreateTransactionManager,
    NTSTATUS,
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LogFileName,
    ULONG CreateOptions,
    ULONG CommitStrength
)

SYSCALL_DEFINE(CreateUserProcess,
    NTSTATUS,
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PVOID ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
)

SYSCALL_DEFINE(CreateWaitCompletionPacket,
    NTSTATUS,
    PHANDLE WaitCompletionPacketHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(CreateWaitablePort,
    NTSTATUS,
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG MaxConnectionInfoLength,
    ULONG MaxMessageLength,
    ULONG MaxPoolUsage
)

SYSCALL_DEFINE(CreateWnfStateName,
    NTSTATUS,
    PCWNF_STATE_NAME StateName,
    WNF_STATE_NAME_LIFETIME NameLifetime,
    WNF_DATA_SCOPE DataScope,
    BOOLEAN PersistData,
    PCWNF_TYPE_ID TypeId,
    ULONG MaximumStateSize,
    PSECURITY_DESCRIPTOR SecurityDescriptor
)

SYSCALL_DEFINE(CreateWorkerFactory,
    NTSTATUS,
    PHANDLE WorkerFactoryHandleReturn,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE CompletionPortHandle,
    HANDLE WorkerProcessHandle,
    PVOID StartRoutine,
    PVOID StartParameter,
    ULONG MaxThreadCount,
    SIZE_T StackReserve,
    SIZE_T StackCommit
)

SYSCALL_DEFINE(DebugActiveProcess,
    NTSTATUS,
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
)

SYSCALL_DEFINE(DebugContinue,
    NTSTATUS,
    HANDLE DebugObjectHandle,
    PCLIENT_ID ClientId,
    NTSTATUS ContinueStatus
)

SYSCALL_DEFINE(DeleteAtom,
    NTSTATUS,
    USHORT Atom
)

SYSCALL_DEFINE(DeleteBootEntry,
    NTSTATUS,
    ULONG Id
)

SYSCALL_DEFINE(DeleteDriverEntry,
    NTSTATUS,
    ULONG Id
)

SYSCALL_DEFINE(DeleteFile,
    NTSTATUS,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(DeleteKey,
    NTSTATUS,
    HANDLE KeyHandle
)

SYSCALL_DEFINE(DeleteObjectAuditAlarm,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PVOID HandleId,
    BOOLEAN GenerateOnClose
)

SYSCALL_DEFINE(DeletePrivateNamespace,
    NTSTATUS,
    HANDLE NamespaceHandle
)

SYSCALL_DEFINE(DeleteValueKey,
    NTSTATUS,
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
)

SYSCALL_DEFINE(DeleteWnfStateData,
    NTSTATUS,
    PCWNF_STATE_NAME StateName,
    PVOID ExplicitScope
)

SYSCALL_DEFINE(DeleteWnfStateName,
    NTSTATUS,
    PCWNF_STATE_NAME StateName
)

SYSCALL_DEFINE(DisableLastKnownGood,
    NTSTATUS
)

SYSCALL_DEFINE(DisplayString,
    NTSTATUS,
    PUNICODE_STRING String
)

SYSCALL_DEFINE(DrawText,
    NTSTATUS,
    PUNICODE_STRING String
)

SYSCALL_DEFINE(EnableLastKnownGood,
    NTSTATUS
)

SYSCALL_DEFINE(EnumerateBootEntries,
    NTSTATUS,
    PVOID Buffer,
    PULONG BufferLength
)

SYSCALL_DEFINE(EnumerateDriverEntries,
    NTSTATUS,
    PVOID Buffer,
    PULONG BufferLength
)

SYSCALL_DEFINE(EnumerateSystemEnvironmentValuesEx,
    NTSTATUS,
    ULONG InformationClass,
    PVOID Buffer,
    PULONG BufferLength
)

SYSCALL_DEFINE(EnumerateTransactionObject,
    NTSTATUS,
    HANDLE RootObjectHandle,
    KTMOBJECT_TYPE QueryType,
    PKTMOBJECT_CURSOR ObjectCursor,
    ULONG ObjectCursorLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(ExtendSection,
    NTSTATUS,
    HANDLE SectionHandle,
    PLARGE_INTEGER NewSectionSize
)

SYSCALL_DEFINE(FilterBootOption,
    NTSTATUS,
    FILTER_BOOT_OPTION_OPERATION FilterOperation,
    ULONG ObjectType,
    ULONG ElementType,
    PVOID SystemData,
    ULONG DataSize
)

SYSCALL_DEFINE(FilterToken,
    NTSTATUS,
    HANDLE ExistingTokenHandle,
    ULONG Flags,
    PTOKEN_GROUPS SidsToDisable,
    PTOKEN_PRIVILEGES PrivilegesToDelete,
    PTOKEN_GROUPS RestrictedSids,
    PHANDLE NewTokenHandle
)

SYSCALL_DEFINE(FilterTokenEx,
    NTSTATUS,
    HANDLE TokenHandle,
    ULONG Flags,
    PTOKEN_GROUPS SidsToDisable,
    PTOKEN_PRIVILEGES PrivilegesToDelete,
    PTOKEN_GROUPS RestrictedSids,
    ULONG DisableUserClaimsCount,
    PUNICODE_STRING UserClaimsToDisable,
    ULONG DisableDeviceClaimsCount,
    PUNICODE_STRING DeviceClaimsToDisable,
    PTOKEN_GROUPS DeviceGroupsToDisable,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes,
    PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes,
    PTOKEN_GROUPS RestrictedDeviceGroups,
    PHANDLE NewTokenHandle
)

SYSCALL_DEFINE(FlushBuffersFileEx,
    NTSTATUS,
    HANDLE FileHandle,
    ULONG Flags,
    PVOID Parameters,
    ULONG ParametersSize,
    PIO_STATUS_BLOCK IoStatusBlock
)

SYSCALL_DEFINE(FlushInstallUILanguage,
    NTSTATUS,
    LANGID InstallUILanguage,
    ULONG SetComittedFlag
)

SYSCALL_DEFINE(FlushInstructionCache,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG Length
)

SYSCALL_DEFINE(FlushKey,
    NTSTATUS,
    HANDLE KeyHandle
)

SYSCALL_DEFINE(FlushProcessWriteBuffers,
    NTSTATUS
)

SYSCALL_DEFINE(FlushVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PULONG RegionSize,
    PIO_STATUS_BLOCK IoStatusBlock
)

SYSCALL_DEFINE(FlushWriteBuffer,
    NTSTATUS
)

SYSCALL_DEFINE(FreeUserPhysicalPages,
    NTSTATUS,
    HANDLE ProcessHandle,
    PULONG NumberOfPages,
    PULONG UserPfnArray
)

SYSCALL_DEFINE(FreezeRegistry,
    NTSTATUS,
    ULONG TimeOutInSeconds
)

SYSCALL_DEFINE(FreezeTransactions,
    NTSTATUS,
    PLARGE_INTEGER FreezeTimeout,
    PLARGE_INTEGER ThawTimeout
)

SYSCALL_DEFINE(GetCachedSigningLevel,
    NTSTATUS,
    HANDLE File,
    PULONG Flags,
    PSE_SIGNING_LEVEL SigningLevel,
    PUCHAR Thumbprint,
    PULONG ThumbprintSize,
    PULONG ThumbprintAlgorithm
)

SYSCALL_DEFINE(GetCompleteWnfStateSubscription,
    NTSTATUS,
    PCWNF_STATE_NAME OldDescriptorStateName,
    PLARGE_INTEGER OldSubscriptionId,
    ULONG OldDescriptorEventMask,
    ULONG OldDescriptorStatus,
    PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
    ULONG DescriptorSize
)

SYSCALL_DEFINE(GetContextThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
)

SYSCALL_DEFINE(GetCurrentProcessorNumber,
    NTSTATUS
)

SYSCALL_DEFINE(GetCurrentProcessorNumberEx,
    NTSTATUS,
    PULONG ProcNumber
)

SYSCALL_DEFINE(GetDevicePowerState,
    NTSTATUS,
    HANDLE Device,
    PDEVICE_POWER_STATE State
)

SYSCALL_DEFINE(GetMUIRegistryInfo,
    NTSTATUS,
    ULONG Flags,
    PULONG DataSize,
    PVOID SystemData
)

SYSCALL_DEFINE(GetNextProcess,
    NTSTATUS,
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
)

SYSCALL_DEFINE(GetNextThread,
    NTSTATUS,
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
)

SYSCALL_DEFINE(GetNlsSectionPtr,
    NTSTATUS,
    ULONG SectionType,
    ULONG SectionData,
    PVOID ContextData,
    PVOID SectionPointer,
    PULONG SectionSize
)

SYSCALL_DEFINE(GetNotificationResourceManager,
    NTSTATUS,
    HANDLE ResourceManagerHandle,
    PTRANSACTION_NOTIFICATION TransactionNotification,
    ULONG NotificationLength,
    PLARGE_INTEGER Timeout,
    PULONG ReturnLength,
    ULONG Asynchronous,
    ULONG AsynchronousContext
)

SYSCALL_DEFINE(GetWriteWatch,
    NTSTATUS,
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID BaseAddress,
    ULONG RegionSize,
    PULONG UserAddressArray,
    PULONG EntriesInUserAddressArray,
    PULONG Granularity
)

SYSCALL_DEFINE(ImpersonateAnonymousToken,
    NTSTATUS,
    HANDLE ThreadHandle
)

SYSCALL_DEFINE(ImpersonateThread,
    NTSTATUS,
    HANDLE ServerThreadHandle,
    HANDLE ClientThreadHandle,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos
)

SYSCALL_DEFINE(InitializeEnclave,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID EnclaveInformation,
    ULONG EnclaveInformationLength,
    PULONG EnclaveError
)

SYSCALL_DEFINE(InitializeNlsFiles,
    NTSTATUS,
    PVOID BaseAddress,
    PLCID DefaultLocaleId,
    PLARGE_INTEGER DefaultCasingTableSize
)

SYSCALL_DEFINE(InitializeRegistry,
    NTSTATUS,
    USHORT BootCondition
)

SYSCALL_DEFINE(InitiatePowerAction,
    NTSTATUS,
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE LightestSystemState,
    ULONG Flags,
    BOOLEAN Asynchronous
)

SYSCALL_DEFINE(IsSystemResumeAutomatic,
    NTSTATUS
)

SYSCALL_DEFINE(IsUILanguageComitted,
    NTSTATUS
)

SYSCALL_DEFINE(ListenPort,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE ConnectionRequest
)

SYSCALL_DEFINE(LoadDriver,
    NTSTATUS,
    PUNICODE_STRING DriverServiceName
)

SYSCALL_DEFINE(LoadEnclaveData,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    ULONG Protect,
    PVOID PageInformation,
    ULONG PageInformationLength,
    PSIZE_T NumberOfBytesWritten,
    PULONG EnclaveError
)

SYSCALL_DEFINE(LoadHotPatch,
    NTSTATUS,
    PUNICODE_STRING HotPatchName,
    ULONG LoadFlag
)

SYSCALL_DEFINE(LoadKey,
    NTSTATUS,
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile
)

SYSCALL_DEFINE(LoadKey2,
    NTSTATUS,
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags
)

SYSCALL_DEFINE(LoadKeyEx,
    NTSTATUS,
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    HANDLE TrustClassKey,
    HANDLE Event,
    ACCESS_MASK DesiredAccess,
    PHANDLE RootHandle,
    PIO_STATUS_BLOCK IoStatus
)

SYSCALL_DEFINE(LockFile,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PULARGE_INTEGER ByteOffset,
    PULARGE_INTEGER Length,
    ULONG Key,
    BOOLEAN FailImmediately,
    BOOLEAN ExclusiveLock
)

SYSCALL_DEFINE(LockProductActivationKeys,
    NTSTATUS,
    PULONG pPrivateVer,
    PULONG pSafeMode
)

SYSCALL_DEFINE(LockRegistryKey,
    NTSTATUS,
    HANDLE KeyHandle
)

SYSCALL_DEFINE(LockVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PULONG RegionSize,
    ULONG MapType
)

SYSCALL_DEFINE(MakePermanentObject,
    NTSTATUS,
    HANDLE Handle
)

SYSCALL_DEFINE(MakeTemporaryObject,
    NTSTATUS,
    HANDLE Handle
)

SYSCALL_DEFINE(ManagePartition,
    NTSTATUS,
    HANDLE TargetHandle,
    HANDLE SourceHandle,
    MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
    PVOID PartitionInformation,
    ULONG PartitionInformationLength
)

SYSCALL_DEFINE(MapCMFModule,
    NTSTATUS,
    ULONG What,
    ULONG Index,
    PULONG CacheIndexOut,
    PULONG CacheFlagsOut,
    PULONG ViewSizeOut,
    PVOID BaseAddress
)

SYSCALL_DEFINE(MapUserPhysicalPages,
    NTSTATUS,
    PVOID VirtualAddress,
    PULONG NumberOfPages,
    PULONG UserPfnArray
)

SYSCALL_DEFINE(MapViewOfSectionEx,
    NTSTATUS,
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PLARGE_INTEGER SectionOffset,
    PPVOID BaseAddress,
    PSIZE_T ViewSize,
    ULONG AllocationType,
    ULONG Protect,
    PVOID DataBuffer,
    ULONG DataCount
)

SYSCALL_DEFINE(ModifyBootEntry,
    NTSTATUS,
    PBOOT_ENTRY BootEntry
)

SYSCALL_DEFINE(ModifyDriverEntry,
    NTSTATUS,
    PEFI_DRIVER_ENTRY DriverEntry
)

SYSCALL_DEFINE(NotifyChangeDirectoryFile,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_NOTIFY_INFORMATION Buffer,
    ULONG Length,
    ULONG CompletionFilter,
    BOOLEAN WatchTree
)

SYSCALL_DEFINE(NotifyChangeDirectoryFileEx,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass
)

SYSCALL_DEFINE(NotifyChangeKey,
    NTSTATUS,
    HANDLE KeyHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer,
    ULONG BufferSize,
    BOOLEAN Asynchronous
)

SYSCALL_DEFINE(NotifyChangeMultipleKeys,
    NTSTATUS,
    HANDLE MasterKeyHandle,
    ULONG Count,
    POBJECT_ATTRIBUTES SubordinateObjects,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer,
    ULONG BufferSize,
    BOOLEAN Asynchronous
)

SYSCALL_DEFINE(NotifyChangeSession,
    NTSTATUS,
    HANDLE SessionHandle,
    ULONG ChangeSequenceNumber,
    PLARGE_INTEGER ChangeTimeStamp,
    IO_SESSION_EVENT Event,
    IO_SESSION_STATE NewState,
    IO_SESSION_STATE PreviousState,
    PVOID Payload,
    ULONG PayloadSize
)

SYSCALL_DEFINE(OpenEnlistment,
    NTSTATUS,
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    LPGUID EnlistmentGuid,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenEventPair,
    NTSTATUS,
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenIoCompletion,
    NTSTATUS,
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenJobObject,
    NTSTATUS,
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenKeyEx,
    NTSTATUS,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions
)

SYSCALL_DEFINE(OpenKeyTransacted,
    NTSTATUS,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE TransactionHandle
)

SYSCALL_DEFINE(OpenKeyTransactedEx,
    NTSTATUS,
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions,
    HANDLE TransactionHandle
)

SYSCALL_DEFINE(OpenKeyedEvent,
    NTSTATUS,
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenMutant,
    NTSTATUS,
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenObjectAuditAlarm,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PVOID HandleId,
    PUNICODE_STRING ObjectTypeName,
    PUNICODE_STRING ObjectName,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    ACCESS_MASK GrantedAccess,
    PPRIVILEGE_SET Privileges,
    BOOLEAN ObjectCreation,
    BOOLEAN AccessGranted,
    PBOOLEAN GenerateOnClose
)

SYSCALL_DEFINE(OpenPartition,
    NTSTATUS,
    PHANDLE PartitionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenPrivateNamespace,
    NTSTATUS,
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID BoundaryDescriptor
)

SYSCALL_DEFINE(OpenProcessToken,
    NTSTATUS,
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle
)

SYSCALL_DEFINE(OpenRegistryTransaction,
    NTSTATUS,
    PHANDLE RegistryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenResourceManager,
    NTSTATUS,
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID ResourceManagerGuid,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenSemaphore,
    NTSTATUS,
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenSession,
    NTSTATUS,
    PHANDLE SessionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenSymbolicLinkObject,
    NTSTATUS,
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenThread,
    NTSTATUS,
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
)

SYSCALL_DEFINE(OpenTimer,
    NTSTATUS,
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
)

SYSCALL_DEFINE(OpenTransaction,
    NTSTATUS,
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    LPGUID Uow,
    HANDLE TmHandle
)

SYSCALL_DEFINE(OpenTransactionManager,
    NTSTATUS,
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LogFileName,
    LPGUID TmIdentity,
    ULONG OpenOptions
)

SYSCALL_DEFINE(PlugPlayControl,
    NTSTATUS,
    PLUGPLAY_CONTROL_CLASS PnPControlClass,
    PVOID PnPControlData,
    ULONG PnPControlDataLength
)

SYSCALL_DEFINE(PrePrepareComplete,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(PrePrepareEnlistment,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(PrepareComplete,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(PrepareEnlistment,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(PrivilegeCheck,
    NTSTATUS,
    HANDLE ClientToken,
    PPRIVILEGE_SET RequiredPrivileges,
    PBOOLEAN Result
)

SYSCALL_DEFINE(PrivilegeObjectAuditAlarm,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PVOID HandleId,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PPRIVILEGE_SET Privileges,
    BOOLEAN AccessGranted
)

SYSCALL_DEFINE(PrivilegedServiceAuditAlarm,
    NTSTATUS,
    PUNICODE_STRING SubsystemName,
    PUNICODE_STRING ServiceName,
    HANDLE ClientToken,
    PPRIVILEGE_SET Privileges,
    BOOLEAN AccessGranted
)

SYSCALL_DEFINE(PropagationComplete,
    NTSTATUS,
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    ULONG BufferLength,
    PVOID Buffer
)

SYSCALL_DEFINE(PropagationFailed,
    NTSTATUS,
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    NTSTATUS PropStatus
)

SYSCALL_DEFINE(PulseEvent,
    NTSTATUS,
    HANDLE EventHandle,
    PULONG PreviousState
)

SYSCALL_DEFINE(QueryAuxiliaryCounterFrequency,
    NTSTATUS,
    PULONGLONG lpAuxiliaryCounterFrequency
)

SYSCALL_DEFINE(QueryBootEntryOrder,
    NTSTATUS,
    PULONG Ids,
    PULONG Count
)

SYSCALL_DEFINE(QueryBootOptions,
    NTSTATUS,
    PBOOT_OPTIONS BootOptions,
    PULONG BootOptionsLength
)

SYSCALL_DEFINE(QueryDebugFilterState,
    NTSTATUS,
    ULONG ComponentId,
    ULONG Level
)

SYSCALL_DEFINE(QueryDirectoryFileEx,
    NTSTATUS,
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags,
    PUNICODE_STRING FileName
)

SYSCALL_DEFINE(QueryDirectoryObject,
    NTSTATUS,
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryDriverEntryOrder,
    NTSTATUS,
    PULONG Ids,
    PULONG Count
)

SYSCALL_DEFINE(QueryEaFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_FULL_EA_INFORMATION Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    PFILE_GET_EA_INFORMATION EaList,
    ULONG EaListLength,
    PULONG EaIndex,
    BOOLEAN RestartScan
)

SYSCALL_DEFINE(QueryFullAttributesFile,
    NTSTATUS,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_NETWORK_OPEN_INFORMATION FileInformation
)

SYSCALL_DEFINE(QueryInformationAtom,
    NTSTATUS,
    USHORT Atom,
    ATOM_INFORMATION_CLASS AtomInformationClass,
    PVOID AtomInformation,
    ULONG AtomInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInformationByName,
    NTSTATUS,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
)

SYSCALL_DEFINE(QueryInformationEnlistment,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInformationJobObject,
    NTSTATUS,
    HANDLE JobHandle,
    JOBOBJECTINFOCLASS JobObjectInformationClass,
    PVOID JobObjectInformation,
    ULONG JobObjectInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInformationPort,
    NTSTATUS,
    HANDLE PortHandle,
    PORT_INFORMATION_CLASS PortInformationClass,
    PVOID PortInformation,
    ULONG Length,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInformationResourceManager,
    NTSTATUS,
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInformationTransaction,
    NTSTATUS,
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInformationTransactionManager,
    NTSTATUS,
    HANDLE TransactionManagerHandle,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInformationWorkerFactory,
    NTSTATUS,
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryInstallUILanguage,
    NTSTATUS,
    PLANGID InstallUILanguageId
)

SYSCALL_DEFINE(QueryIntervalProfile,
    NTSTATUS,
    KPROFILE_SOURCE ProfileSource,
    PULONG Interval
)

SYSCALL_DEFINE(QueryIoCompletion,
    NTSTATUS,
    HANDLE IoCompletionHandle,
    IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    PVOID IoCompletionInformation,
    ULONG IoCompletionInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryLicenseValue,
    NTSTATUS,
    PUNICODE_STRING ValueName,
    PULONG Type,
    PVOID SystemData,
    ULONG DataSize,
    PULONG ResultDataSize
)

SYSCALL_DEFINE(QueryMultipleValueKey,
    NTSTATUS,
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength
)

SYSCALL_DEFINE(QueryMutant,
    NTSTATUS,
    HANDLE MutantHandle,
    MUTANT_INFORMATION_CLASS MutantInformationClass,
    PVOID MutantInformation,
    ULONG MutantInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryOpenSubKeys,
    NTSTATUS,
    POBJECT_ATTRIBUTES TargetKey,
    PULONG HandleCount
)

SYSCALL_DEFINE(QueryOpenSubKeysEx,
    NTSTATUS,
    POBJECT_ATTRIBUTES TargetKey,
    ULONG BufferLength,
    PVOID Buffer,
    PULONG RequiredSize
)

SYSCALL_DEFINE(QueryPortInformationProcess,
    NTSTATUS
)

SYSCALL_DEFINE(QueryQuotaInformationFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_USER_QUOTA_INFORMATION Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    PFILE_QUOTA_LIST_INFORMATION SidList,
    ULONG SidListLength,
    PSID StartSid,
    BOOLEAN RestartScan
)

SYSCALL_DEFINE(QuerySecurityAttributesToken,
    NTSTATUS,
    HANDLE TokenHandle,
    PUNICODE_STRING Attributes,
    ULONG NumberOfAttributes,
    PVOID Buffer,
    ULONG Length,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QuerySecurityObject,
    NTSTATUS,
    HANDLE Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG Length,
    PULONG LengthNeeded
)

SYSCALL_DEFINE(QuerySecurityPolicy,
    NTSTATUS,
    ULONG_PTR UnknownParameter1,
    ULONG_PTR UnknownParameter2,
    ULONG_PTR UnknownParameter3,
    ULONG_PTR UnknownParameter4,
    ULONG_PTR UnknownParameter5,
    ULONG_PTR UnknownParameter6
)

SYSCALL_DEFINE(QuerySemaphore,
    NTSTATUS,
    HANDLE SemaphoreHandle,
    SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    PVOID SemaphoreInformation,
    ULONG SemaphoreInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QuerySymbolicLinkObject,
    NTSTATUS,
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength
)

SYSCALL_DEFINE(QuerySystemEnvironmentValue,
    NTSTATUS,
    PUNICODE_STRING VariableName,
    PVOID VariableValue,
    ULONG ValueLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QuerySystemEnvironmentValueEx,
    NTSTATUS,
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    PULONG ValueLength,
    PULONG Attributes
)

SYSCALL_DEFINE(QuerySystemInformationEx,
    NTSTATUS,
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(QueryTimerResolution,
    NTSTATUS,
    PULONG MaximumTime,
    PULONG MinimumTime,
    PULONG CurrentTime
)

SYSCALL_DEFINE(QueryWnfStateData,
    NTSTATUS,
    PCWNF_STATE_NAME StateName,
    PCWNF_TYPE_ID TypeId,
    PVOID ExplicitScope,
    PWNF_CHANGE_STAMP ChangeStamp,
    PVOID Buffer,
    PULONG BufferSize
)

SYSCALL_DEFINE(QueryWnfStateNameInformation,
    NTSTATUS,
    PCWNF_STATE_NAME StateName,
    PCWNF_TYPE_ID NameInfoClass,
    PVOID ExplicitScope,
    PVOID InfoBuffer,
    ULONG InfoBufferSize
)

SYSCALL_DEFINE(QueueApcThreadEx,
    NTSTATUS,
    HANDLE ThreadHandle,
    HANDLE UserApcReserveHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
)

SYSCALL_DEFINE(RaiseException,
    NTSTATUS,
    PEXCEPTION_RECORD ExceptionRecord,
    PCONTEXT ContextRecord,
    BOOLEAN FirstChance
)

SYSCALL_DEFINE(RaiseHardError,
    NTSTATUS,
    NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask,
    PULONG_PTR Parameters,
    ULONG ValidResponseOptions,
    PULONG Response
)

SYSCALL_DEFINE(ReadOnlyEnlistment,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(RecoverEnlistment,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PVOID EnlistmentKey
)

SYSCALL_DEFINE(RecoverResourceManager,
    NTSTATUS,
    HANDLE ResourceManagerHandle
)

SYSCALL_DEFINE(RecoverTransactionManager,
    NTSTATUS,
    HANDLE TransactionManagerHandle
)

SYSCALL_DEFINE(RegisterProtocolAddressInformation,
    NTSTATUS,
    HANDLE ResourceManager,
    LPGUID ProtocolId,
    ULONG ProtocolInformationSize,
    PVOID ProtocolInformation,
    ULONG CreateOptions
)

SYSCALL_DEFINE(RegisterThreadTerminatePort,
    NTSTATUS,
    HANDLE PortHandle
)

SYSCALL_DEFINE(ReleaseKeyedEvent,
    NTSTATUS,
    HANDLE KeyedEventHandle,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(ReleaseWorkerFactoryWorker,
    NTSTATUS,
    HANDLE WorkerFactoryHandle
)

SYSCALL_DEFINE(RemoveIoCompletionEx,
    NTSTATUS,
    HANDLE IoCompletionHandle,
    PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
    ULONG Count,
    PULONG NumEntriesRemoved,
    PLARGE_INTEGER Timeout,
    BOOLEAN Alertable
)

SYSCALL_DEFINE(RemoveProcessDebug,
    NTSTATUS,
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
)

SYSCALL_DEFINE(RenameKey,
    NTSTATUS,
    HANDLE KeyHandle,
    PUNICODE_STRING NewName
)

SYSCALL_DEFINE(RenameTransactionManager,
    NTSTATUS,
    PUNICODE_STRING LogFileName,
    LPGUID ExistingTransactionManagerGuid
)

SYSCALL_DEFINE(ReplaceKey,
    NTSTATUS,
    POBJECT_ATTRIBUTES NewFile,
    HANDLE TargetHandle,
    POBJECT_ATTRIBUTES OldFile
)

SYSCALL_DEFINE(ReplacePartitionUnit,
    NTSTATUS,
    PUNICODE_STRING TargetInstancePath,
    PUNICODE_STRING SpareInstancePath,
    ULONG Flags
)

SYSCALL_DEFINE(ReplyWaitReplyPort,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage
)

SYSCALL_DEFINE(RequestPort,
    NTSTATUS,
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage
)

SYSCALL_DEFINE(ResetEvent,
    NTSTATUS,
    HANDLE EventHandle,
    PULONG PreviousState
)

SYSCALL_DEFINE(ResetWriteWatch,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG RegionSize
)

SYSCALL_DEFINE(RestoreKey,
    NTSTATUS,
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Flags
)

SYSCALL_DEFINE(ResumeProcess,
    NTSTATUS,
    HANDLE ProcessHandle
)

SYSCALL_DEFINE(RevertContainerImpersonation,
    NTSTATUS
)

SYSCALL_DEFINE(RollbackComplete,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(RollbackEnlistment,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(RollbackRegistryTransaction,
    NTSTATUS,
    HANDLE RegistryHandle,
    BOOL Wait
)

SYSCALL_DEFINE(RollbackTransaction,
    NTSTATUS,
    HANDLE TransactionHandle,
    BOOLEAN Wait
)

SYSCALL_DEFINE(RollforwardTransactionManager,
    NTSTATUS,
    HANDLE TransactionManagerHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(SaveKey,
    NTSTATUS,
    HANDLE KeyHandle,
    HANDLE FileHandle
)

SYSCALL_DEFINE(SaveKeyEx,
    NTSTATUS,
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Format
)

SYSCALL_DEFINE(SaveMergedKeys,
    NTSTATUS,
    HANDLE HighPrecedenceKeyHandle,
    HANDLE LowPrecedenceKeyHandle,
    HANDLE FileHandle
)

SYSCALL_DEFINE(SecureConnectPort,
    NTSTATUS,
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_SECTION_WRITE ClientView,
    PSID RequiredServerSid,
    PPORT_SECTION_READ ServerView,
    PULONG MaxMessageLength,
    PVOID ConnectionInformation,
    PULONG ConnectionInformationLength
)

SYSCALL_DEFINE(SerializeBoot,
    NTSTATUS
)

SYSCALL_DEFINE(SetBootEntryOrder,
    NTSTATUS,
    PULONG Ids,
    ULONG Count
)

SYSCALL_DEFINE(SetBootOptions,
    NTSTATUS,
    PBOOT_OPTIONS BootOptions,
    ULONG FieldsToChange
)

SYSCALL_DEFINE(SetCachedSigningLevel,
    NTSTATUS,
    ULONG Flags,
    SE_SIGNING_LEVEL InputSigningLevel,
    PHANDLE SourceFiles,
    ULONG SourceFileCount,
    HANDLE TargetFile
)

SYSCALL_DEFINE(SetCachedSigningLevel2,
    NTSTATUS,
    ULONG Flags,
    ULONG InputSigningLevel,
    PHANDLE SourceFiles,
    ULONG SourceFileCount,
    HANDLE TargetFile,
    PVOID LevelInformation
)

SYSCALL_DEFINE(SetContextThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    PCONTEXT Context
)

SYSCALL_DEFINE(SetDebugFilterState,
    NTSTATUS,
    ULONG ComponentId,
    ULONG Level,
    BOOLEAN State
)

SYSCALL_DEFINE(SetDefaultHardErrorPort,
    NTSTATUS,
    HANDLE PortHandle
)

SYSCALL_DEFINE(SetDefaultLocale,
    NTSTATUS,
    BOOLEAN UserProfile,
    LCID DefaultLocaleId
)

SYSCALL_DEFINE(SetDefaultUILanguage,
    NTSTATUS,
    LANGID DefaultUILanguageId
)

SYSCALL_DEFINE(SetDriverEntryOrder,
    NTSTATUS,
    PULONG Ids,
    PULONG Count
)

SYSCALL_DEFINE(SetEaFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_FULL_EA_INFORMATION EaBuffer,
    ULONG EaBufferSize
)

SYSCALL_DEFINE(SetHighEventPair,
    NTSTATUS,
    HANDLE EventPairHandle
)

SYSCALL_DEFINE(SetHighWaitLowEventPair,
    NTSTATUS,
    HANDLE EventPairHandle
)

SYSCALL_DEFINE(SetIRTimer,
    NTSTATUS,
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime
)

SYSCALL_DEFINE(SetInformationDebugObject,
    NTSTATUS,
    HANDLE DebugObject,
    DEBUGOBJECTINFOCLASS InformationClass,
    PVOID Information,
    ULONG InformationLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(SetInformationEnlistment,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength
)

SYSCALL_DEFINE(SetInformationJobObject,
    NTSTATUS,
    HANDLE JobHandle,
    JOBOBJECTINFOCLASS JobObjectInformationClass,
    PVOID JobObjectInformation,
    ULONG JobObjectInformationLength
)

SYSCALL_DEFINE(SetInformationKey,
    NTSTATUS,
    HANDLE KeyHandle,
    KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    PVOID KeySetInformation,
    ULONG KeySetInformationLength
)

SYSCALL_DEFINE(SetInformationResourceManager,
    NTSTATUS,
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength
)

SYSCALL_DEFINE(SetInformationSymbolicLink,
    NTSTATUS,
    HANDLE Handle,
    ULONG Class,
    PVOID Buffer,
    ULONG BufferLength
)

SYSCALL_DEFINE(SetInformationToken,
    NTSTATUS,
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength
)

SYSCALL_DEFINE(SetInformationTransaction,
    NTSTATUS,
    HANDLE TransactionHandle,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength
)

SYSCALL_DEFINE(SetInformationTransactionManager,
    NTSTATUS,
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength
)

SYSCALL_DEFINE(SetInformationVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    ULONG_PTR NumberOfEntries,
    PMEMORY_RANGE_ENTRY VirtualAddresses,
    PVOID VmInformation,
    ULONG VmInformationLength
)

SYSCALL_DEFINE(SetInformationWorkerFactory,
    NTSTATUS,
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
)

SYSCALL_DEFINE(SetIntervalProfile,
    NTSTATUS,
    ULONG Interval,
    KPROFILE_SOURCE Source
)

SYSCALL_DEFINE(SetIoCompletion,
    NTSTATUS,
    HANDLE IoCompletionHandle,
    ULONG CompletionKey,
    PIO_STATUS_BLOCK IoStatusBlock,
    NTSTATUS CompletionStatus,
    ULONG NumberOfBytesTransfered
)

SYSCALL_DEFINE(SetIoCompletionEx,
    NTSTATUS,
    HANDLE IoCompletionHandle,
    HANDLE IoCompletionPacketHandle,
    PVOID KeyContext,
    PVOID ApcContext,
    NTSTATUS IoStatus,
    ULONG_PTR IoStatusInformation
)

SYSCALL_DEFINE(SetLdtEntries,
    NTSTATUS,
    ULONG Selector0,
    ULONG Entry0Low,
    ULONG Entry0Hi,
    ULONG Selector1,
    ULONG Entry1Low,
    ULONG Entry1Hi
)

SYSCALL_DEFINE(SetLowEventPair,
    NTSTATUS,
    HANDLE EventPairHandle
)

SYSCALL_DEFINE(SetLowWaitHighEventPair,
    NTSTATUS,
    HANDLE EventPairHandle
)

SYSCALL_DEFINE(SetQuotaInformationFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PFILE_USER_QUOTA_INFORMATION Buffer,
    ULONG Length
)

SYSCALL_DEFINE(SetSecurityObject,
    NTSTATUS,
    HANDLE ObjectHandle,
    SECURITY_INFORMATION SecurityInformationClass,
    PSECURITY_DESCRIPTOR DescriptorBuffer
)

SYSCALL_DEFINE(SetSystemEnvironmentValue,
    NTSTATUS,
    PUNICODE_STRING VariableName,
    PUNICODE_STRING Value
)

SYSCALL_DEFINE(SetSystemEnvironmentValueEx,
    NTSTATUS,
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    ULONG ValueLength,
    ULONG Attributes
)

SYSCALL_DEFINE(SetSystemInformation,
    NTSTATUS,
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
)

SYSCALL_DEFINE(SetSystemPowerState,
    NTSTATUS,
    POWER_ACTION SystemAction,
    SYSTEM_POWER_STATE MinSystemState,
    ULONG Flags
)

SYSCALL_DEFINE(SetSystemTime,
    NTSTATUS,
    PLARGE_INTEGER SystemTime,
    PLARGE_INTEGER PreviousTime
)

SYSCALL_DEFINE(SetThreadExecutionState,
    NTSTATUS,
    EXECUTION_STATE ExecutionState,
    PEXECUTION_STATE PreviousExecutionState
)

SYSCALL_DEFINE(SetTimer2,
    NTSTATUS,
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PLARGE_INTEGER Period,
    PT2_SET_PARAMETERS Parameters
)

SYSCALL_DEFINE(SetTimerEx,
    NTSTATUS,
    HANDLE TimerHandle,
    TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    PVOID TimerSetInformation,
    ULONG TimerSetInformationLength
)

SYSCALL_DEFINE(SetTimerResolution,
    NTSTATUS,
    ULONG DesiredResolution,
    BOOLEAN SetResolution,
    PULONG CurrentResolution
)

SYSCALL_DEFINE(SetUuidSeed,
    NTSTATUS,
    PUCHAR Seed
)

SYSCALL_DEFINE(SetVolumeInformationFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileSystemInformation,
    ULONG Length,
    FSINFOCLASS FileSystemInformationClass
)

SYSCALL_DEFINE(SetWnfProcessNotificationEvent,
    NTSTATUS,
    HANDLE NotificationEvent
)

SYSCALL_DEFINE(ShutdownSystem,
    NTSTATUS,
    SHUTDOWN_ACTION Action
)

SYSCALL_DEFINE(ShutdownWorkerFactory,
    NTSTATUS,
    HANDLE WorkerFactoryHandle,
    PLONG PendingWorkerCount
)

SYSCALL_DEFINE(SignalAndWaitForSingleObject,
    NTSTATUS,
    HANDLE hObjectToSignal,
    HANDLE hObjectToWaitOn,
    BOOLEAN bAlertable,
    PLARGE_INTEGER dwMilliseconds
)

SYSCALL_DEFINE(SinglePhaseReject,
    NTSTATUS,
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(StartProfile,
    NTSTATUS,
    HANDLE ProfileHandle
)

SYSCALL_DEFINE(StopProfile,
    NTSTATUS,
    HANDLE ProfileHandle
)

SYSCALL_DEFINE(SubscribeWnfStateChange,
    NTSTATUS,
    PCWNF_STATE_NAME StateName,
    WNF_CHANGE_STAMP ChangeStamp,
    ULONG EventMask,
    PLARGE_INTEGER SubscriptionId
)

SYSCALL_DEFINE(SuspendProcess,
    NTSTATUS,
    HANDLE ProcessHandle
)

SYSCALL_DEFINE(SuspendThread,
    NTSTATUS,
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
)

SYSCALL_DEFINE(SystemDebugControl,
    NTSTATUS,
    DEBUG_CONTROL_CODE Command,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(TerminateEnclave,
    NTSTATUS,
    PVOID BaseAddress,
    BOOLEAN WaitForThread
)

SYSCALL_DEFINE(TerminateJobObject,
    NTSTATUS,
    HANDLE JobHandle,
    NTSTATUS ExitStatus
)

SYSCALL_DEFINE(TestAlert,
    NTSTATUS
)

SYSCALL_DEFINE(ThawRegistry,
    NTSTATUS
)

SYSCALL_DEFINE(ThawTransactions,
    NTSTATUS
)

SYSCALL_DEFINE(TraceControl,
    NTSTATUS,
    ULONG FunctionCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnLength
)

SYSCALL_DEFINE(TranslateFilePath,
    NTSTATUS,
    PFILE_PATH InputFilePath,
    ULONG OutputType,
    PFILE_PATH OutputFilePath,
    PULONG OutputFilePathLength
)

SYSCALL_DEFINE(UmsThreadYield,
    NTSTATUS,
    PVOID SchedulerParam
)

SYSCALL_DEFINE(UnloadDriver,
    NTSTATUS,
    PUNICODE_STRING DriverServiceName
)

SYSCALL_DEFINE(UnloadKey,
    NTSTATUS,
    POBJECT_ATTRIBUTES DestinationKeyName
)

SYSCALL_DEFINE(UnloadKey2,
    NTSTATUS,
    POBJECT_ATTRIBUTES TargetKey,
    ULONG Flags
)

SYSCALL_DEFINE(UnloadKeyEx,
    NTSTATUS,
    POBJECT_ATTRIBUTES TargetKey,
    HANDLE Event
)

SYSCALL_DEFINE(UnlockFile,
    NTSTATUS,
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PULARGE_INTEGER ByteOffset,
    PULARGE_INTEGER Length,
    ULONG Key
)

SYSCALL_DEFINE(UnlockVirtualMemory,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToUnlock,
    ULONG LockType
)

SYSCALL_DEFINE(UnmapViewOfSectionEx,
    NTSTATUS,
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG Flags
)

SYSCALL_DEFINE(UnsubscribeWnfStateChange,
    NTSTATUS,
    PCWNF_STATE_NAME StateName
)

SYSCALL_DEFINE(UpdateWnfStateData,
    NTSTATUS,
    PCWNF_STATE_NAME StateName,
    PVOID Buffer,
    ULONG Length,
    PCWNF_TYPE_ID TypeId,
    PVOID ExplicitScope,
    WNF_CHANGE_STAMP MatchingChangeStamp,
    ULONG CheckStamp
)

SYSCALL_DEFINE(VdmControl,
    NTSTATUS,
    VDMSERVICECLASS Service,
    PVOID ServiceData
)

SYSCALL_DEFINE(WaitForAlertByThreadId,
    NTSTATUS,
    HANDLE Handle,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(WaitForDebugEvent,
    NTSTATUS,
    HANDLE DebugObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout,
    PVOID WaitStateChange
)

SYSCALL_DEFINE(WaitForKeyedEvent,
    NTSTATUS,
    HANDLE KeyedEventHandle,
    PVOID Key,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
)

SYSCALL_DEFINE(WaitForWorkViaWorkerFactory,
    NTSTATUS,
    HANDLE WorkerFactoryHandle,
    PVOID MiniPacket
)

SYSCALL_DEFINE(WaitHighEventPair,
    NTSTATUS,
    HANDLE EventHandle
)

SYSCALL_DEFINE(WaitLowEventPair,
    NTSTATUS,
    HANDLE EventHandle
)

SYSCALL_DEFINE(AcquireCMFViewOwnership,
    NTSTATUS,
    BOOLEAN TimeStamp,
    BOOLEAN TokenTaken,
    BOOLEAN ReplaceExisting
)

SYSCALL_DEFINE(CancelDeviceWakeupRequest,
    NTSTATUS,
    HANDLE DeviceHandle
)

SYSCALL_DEFINE(ClearAllSavepointsTransaction,
    NTSTATUS,
    HANDLE TransactionHandle
)

SYSCALL_DEFINE(ClearSavepointTransaction,
    NTSTATUS,
    HANDLE TransactionHandle,
    ULONG SavePointId
)

SYSCALL_DEFINE(RollbackSavepointTransaction,
    NTSTATUS,
    HANDLE TransactionHandle,
    ULONG SavePointId
)

SYSCALL_DEFINE(SavepointTransaction,
    NTSTATUS,
    HANDLE TransactionHandle,
    BOOLEAN Flag,
    ULONG SavePointId
)

SYSCALL_DEFINE(SavepointComplete,
    NTSTATUS,
    HANDLE TransactionHandle,
    PLARGE_INTEGER TmVirtualClock
)

SYSCALL_DEFINE(CreateSectionEx,
    NTSTATUS,
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParametersCount
)

SYSCALL_DEFINE(CreateCrossVmEvent,
    NTSTATUS
)

SYSCALL_DEFINE(ListTransactions,
    NTSTATUS
)

SYSCALL_DEFINE(MarshallTransaction,
    NTSTATUS
)

SYSCALL_DEFINE(PullTransaction,
    NTSTATUS
)

SYSCALL_DEFINE(ReleaseCMFViewOwnership,
    NTSTATUS
)

SYSCALL_DEFINE(WaitForWnfNotifications,
    NTSTATUS
)

SYSCALL_DEFINE(StartTm,
    NTSTATUS
)

SYSCALL_DEFINE(SetInformationProcess,
    NTSTATUS,
    HANDLE DeviceHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG Length
)

SYSCALL_DEFINE(RequestDeviceWakeup,
    NTSTATUS,
    HANDLE DeviceHandle
)

SYSCALL_DEFINE(RequestWakeupLatency,
    NTSTATUS,
    ULONG LatencyTime
)

SYSCALL_DEFINE(QuerySystemTime,
    NTSTATUS,
    PLARGE_INTEGER SystemTime
)

SYSCALL_DEFINE(ManageHotPatch,
    NTSTATUS,
    ULONG UnknownParameter1,
    ULONG UnknownParameter2,
    ULONG UnknownParameter3,
    ULONG UnknownParameter4
)

SYSCALL_DEFINE(ContinueEx,
    NTSTATUS,
    PCONTEXT ContextRecord,
    PKCONTINUE_ARGUMENT ContinueArgument
)
