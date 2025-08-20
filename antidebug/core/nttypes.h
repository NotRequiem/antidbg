#include <windows.h>

typedef struct _Dbg_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} Dbg_PEB_LDR_DATA, * PDbg_PEB_LDR_DATA;

typedef struct _Dbg_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} Dbg_LDR_DATA_TABLE_ENTRY, * PDbg_LDR_DATA_TABLE_ENTRY;

typedef struct _Dbg_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PDbg_PEB_LDR_DATA Ldr;
} Dbg_PEB, * PDbg_PEB;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE, * PPS_CREATE_STATE;

typedef enum _KCONTINUE_TYPE
{
	KCONTINUE_UNWIND,
	KCONTINUE_RESUME,
	KCONTINUE_LONGJUMP,
	KCONTINUE_SET,
	KCONTINUE_LAST
} KCONTINUE_TYPE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID* Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _API_SET_NAMESPACE
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _ACTIVATION_CONTEXT* PACTIVATION_CONTEXT;

typedef struct _ACTIVATION_CONTEXT_DATA
{
	ULONG Magic;
	ULONG HeaderSize;
	ULONG FormatVersion;
	ULONG TotalSize;
	ULONG DefaultTocOffset;
	ULONG ExtendedTocOffset;
	ULONG AssemblyRosterOffset;
	ULONG Flags;
} ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TELEMETRY_COVERAGE_HEADER
{
	UCHAR MajorVersion;
	UCHAR MinorVersion;
	struct
	{
		USHORT TracingEnabled : 1;
		USHORT Reserved1 : 15;
	};
	ULONG HashTableEntries;
	ULONG HashIndexMask;
	ULONG TableUpdateVersion;
	ULONG TableSizeInBytes;
	ULONG LastResetTick;
	ULONG ResetRound;
	ULONG Reserved2;
	ULONG RecordedCount;
	ULONG Reserved3[4];
	ULONG HashTable[ANYSIZE_ARRAY];
} TELEMETRY_COVERAGE_HEADER, * PTELEMETRY_COVERAGE_HEADER;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif
typedef struct _RTL_USER_PROCESS_PARAMETERS* PRTL_USER_PROCESS_PARAMETERS;
typedef struct _RTL_BITMAP* PRTL_BITMAP;
typedef struct _SILO_USER_SHARED_DATA* PSILO_USER_SHARED_DATA;
typedef struct _LEAP_SECOND_DATA* PLEAP_SECOND_DATA;
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PSLIST_HEADER AtlThunkSListPtr;
	PVOID IFEOKey;

	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PRTL_BITMAP TlsBitmap;
	ULONG TlsBitmapBits[2];

	PVOID ReadOnlySharedMemoryBase;
	PSILO_USER_SHARED_DATA SharedData;
	PVOID* ReadOnlyStaticServerData;

	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	KAFFINITY ActiveProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PRTL_BITMAP TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;

	// UNICODE_STRING CSDVersion;

	PACTIVATION_CONTEXT_DATA ActivationContextData;
	// PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
	PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
	// PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

	SIZE_T MinimumStackCommit;

	PVOID SparePointers[2];
	PVOID PatchLoaderData;
	PVOID ChpeV2ProcessInfo;

	ULONG AppModelFeatureState;
	ULONG SpareUlongs[2];

	USHORT ActiveCodePage;
	USHORT OemCodePage;
	USHORT UseCaseMapping;
	USHORT UnusedNlsField;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;

	union
	{
		PVOID pContextData;
		PVOID pUnused;
		PVOID EcCodeBitMap; // WIN11
	};

	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PRTL_CRITICAL_SECTION TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
	PTELEMETRY_COVERAGE_HEADER TelemetryCoverageHeader;
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags;
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	PLEAP_SECOND_DATA LeapSecondData;
	union
	{
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
	ULONGLONG ExtendedFeatureDisableMask; // since WIN11
} PEB, * PPEB;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG_PTR HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

#define WIN32_CLIENT_INFO_LENGTH 62
#define STATIC_UNICODE_BUFFER_LENGTH 261

typedef struct _TEB
{
	NT_TIB NtTib;

	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
	PVOID SystemReserved1[30];
#else
	PVOID SystemReserved1[26];
#endif

	CHAR PlaceholderCompatibilityMode;
	BOOLEAN PlaceholderHydrationAlwaysExplicit;
	CHAR PlaceholderReserved[10];

	ULONG ProxiedProcessId;
	ACTIVATION_CONTEXT_STACK ActivationStack;

	UCHAR WorkingOnBehalfTicket[8];
	NTSTATUS ExceptionCode;

	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	ULONG_PTR InstrumentationCallbackSp;
	ULONG_PTR InstrumentationCallbackPreviousPc;
	ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
	ULONG TxFsContext;
#endif

	BOOLEAN InstrumentationCallbackDisabled;
#ifdef _WIN64
	BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifndef _WIN64
	UCHAR SpareBytes[23];
	ULONG TxFsContext;
#endif
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];

	PVOID DeallocationStack;
	PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];
	LIST_ENTRY TlsLinks;

	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];

	ULONG HardErrorMode;
#ifdef _WIN64
	PVOID Instrumentation[11];
#else
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;

	PVOID SubProcessTag;
	PVOID PerflibData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;

	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		};
	};

	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle; // tagSOleTlsData
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR ReservedForCodeCoverage;
	PVOID ThreadPoolData;
	PVOID* TlsExpansionSlots;
#ifdef _WIN64
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
#endif
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapData;
	HANDLE CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;

	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;

	union
	{
		USHORT CrossTebFlags;
		USHORT SpareCrossTebBits : 16;
	};
	union
	{
		USHORT SameTebFlags;
		struct
		{
			USHORT SafeThunkCall : 1;
			USHORT InDebugPrint : 1;
			USHORT HasFiberData : 1;
			USHORT SkipThreadAttach : 1;
			USHORT WerInShipAssertCode : 1;
			USHORT RanProcessInit : 1;
			USHORT ClonedThread : 1;
			USHORT SuppressDebugMsg : 1;
			USHORT DisableUserStackWalk : 1;
			USHORT RtlExceptionAttached : 1;
			USHORT InitialThread : 1;
			USHORT SessionAware : 1;
			USHORT LoadOwner : 1;
			USHORT LoaderWorker : 1;
			USHORT SkipLoaderInit : 1;
			USHORT SkipFileAPIBrokering : 1;
		};
	};

	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	LONG WowTebOffset;
	PVOID ResourceRetValue;
	PVOID ReservedForWdf;
	ULONGLONG ReservedForCrt;
	GUID EffectiveContainerId;
	ULONGLONG LastSleepCounter; // since Windows 11
	ULONG SpinCallCount;
	ULONGLONG ExtendedFeatureDisableMask;
} TEB, * PTEB;

#pragma warning (default: 4201)

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	InvalidIDEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, * PPLUGPLAY_EVENT_CATEGORY;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;
	union
	{
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, * PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _WNF_STATE_NAME
{
	ULONG Data[2];
} WNF_STATE_NAME, * PWNF_STATE_NAME;

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG           DataLength;
	ULONG           DataOffset;
	ULONG           Type;
} KEY_VALUE_ENTRY, * PKEY_VALUE_ENTRY;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum.
} KEY_SET_INFORMATION_CLASS, * PKEY_SET_INFORMATION_CLASS;

#ifndef _SYSTEM_INFORMATION_CLASS
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformationNative,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation
} SYSTEM_INFORMATION_CLASS;
#endif

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,            // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits,                 // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters,                  // q: IO_COUNTERS
	ProcessVmCounters,                  // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes,                       // q: KERNEL_USER_TIMES
	ProcessBasePriority,                // s: KPRIORITY
	ProcessRaisePriority,               // s: ULONG
	ProcessDebugPort,                   // q: HANDLE
	ProcessExceptionPort,               // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
	ProcessAccessToken,                 // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation,              // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize,                     // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode,        // qs: ULONG
	ProcessIoPortHandlers,              // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
	ProcessPooledUsageAndLimits,        // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch,             // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,                // qs: ULONG (requires SeTcbPrivilege)
	ProcessEnableAlignmentFaultFixup,   // s: BOOLEAN
	ProcessPriorityClass,               // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,             // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
	ProcessHandleCount,                 // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask,                // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
	ProcessPriorityBoost,               // qs: ULONG
	ProcessDeviceMap,                   // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation,          // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation,       // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information,            // q: ULONG_PTR
	ProcessImageFileName,               // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled,       // q: ULONG
	ProcessBreakOnTermination,          // qs: ULONG
	ProcessDebugObjectHandle,           // q: HANDLE // 30
	ProcessDebugFlags,                  // qs: ULONG
	ProcessHandleTracing,               // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority,                  // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags,                // qs: ULONG
	ProcessTlsInformation,              // PROCESS_TLS_INFORMATION // ProcessResourceManagement
	ProcessCookie,                      // q: ULONG
	ProcessImageInformation,            // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime,                   // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority,                // qs: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback,     // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation,       // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx,           // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32,          // q: UNICODE_STRING
	ProcessImageFileMapping,            // q: HANDLE (input)
	ProcessAffinityUpdateMode,          // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode,        // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation,            // q: USHORT[]
	ProcessTokenVirtualizationEnabled,  // s: ULONG
	ProcessConsoleHostProcess,          // q: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation,           // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation,           // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy,            // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,         // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount,             // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles,          // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl,          // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable,                // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode,      // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
	ProcessCommandLineInformation,     // q: UNICODE_STRING // 60
	ProcessProtectionInformation,      // q: PS_PROTECTION
	ProcessMemoryExhaustion,           // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation,           // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation,     // q: PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation,   // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,  // SYSTEM_CPU_SET_INFORMATION[5]
	ProcessAllowedCpuSetsInformation,  // SYSTEM_CPU_SET_INFORMATION[5]
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation,                  // q: PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate,                             // s: void // ETW // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose,  // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation,          // q: PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation,  // qs: BOOLEAN (requires SeTcbPrivilege)
	ProcessSubsystemInformation,             // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues,                     // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessPowerThrottlingState,             // qs: POWER_THROTTLING_PROCESS_STATE
	ProcessReserved3Information,             // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation,   // q: WIN32K_SYSCALL_FILTER
	ProcessDisableSystemAllowedCpuSets,      // 80
	ProcessWakeInformation,                  // PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState,              // PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory,   // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging,            // PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation,                   // q: PROCESS_UPTIME_INFORMATION
	ProcessImageSection,                        // q: HANDLE
	ProcessDebugAuthInformation,                // since REDSTONE4 // 90
	ProcessSystemResourceManagement,            // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber,                      // q: ULONGLONG
	ProcessLoaderDetour,                        // since REDSTONE5
	ProcessSecurityDomainInformation,           // PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation,   // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging,                       // PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation,               // PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation,          // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
	ProcessFreeFiberShadowStackAllocation,      // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	ProcessAltSystemCallInformation,            // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
	ProcessDynamicEHContinuationTargets,        // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
	ProcessDynamicEnforcedCetCompatibleRanges,  // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
	ProcessCreateStateChange,                   // since WIN11
	ProcessApplyStateChange,
	ProcessEnableOptionalXStateFeatures,
	ProcessAltPrefetchParam,  // since 22H1
	ProcessAssignCpuPartitions,
	ProcessPriorityClassEx,  // s: PROCESS_PRIORITY_CLASS_EX
	ProcessMembershipInformation,
	ProcessEffectiveIoPriority,    // q: IO_PRIORITY_HINT
	ProcessEffectivePagePriority,  // q: ULONG
	MaxProcessInfoClass
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG    Version;
	ULONG    Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef struct _FILE_PATH
{
	ULONG Version;
	ULONG Length;
	ULONG Type;
	CHAR  FilePath[1];
} FILE_PATH, * PFILE_PATH;

typedef struct _FILE_USER_QUOTA_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         SidLength;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER QuotaUsed;
	LARGE_INTEGER QuotaThreshold;
	LARGE_INTEGER QuotaLimit;
	SID           Sid[1];
} FILE_USER_QUOTA_INFORMATION, * PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	SID   Sid[1];
} FILE_QUOTA_LIST_INFORMATION, * PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
	ULONG         Unknown;
} FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
	FilterBootOptionOperationOpenSystemStore,
	FilterBootOptionOperationSetElement,
	FilterBootOptionOperationDeleteElement,
	FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION, * PFILTER_BOOT_OPTION_OPERATION;

typedef enum _EVENT_TYPE
{
	NotificationEvent = 0,
	SynchronizationEvent = 1,
} EVENT_TYPE, * PEVENT_TYPE;

typedef struct _FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	BYTE  EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, * PFILE_GET_EA_INFORMATION;

typedef struct _BOOT_OPTIONS
{
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, * PBOOT_OPTIONS;

typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem = 0,
	WnfDataScopeSession = 1,
	WnfDataScopeUser = 2,
	WnfDataScopeProcess = 3,
	WnfDataScopeMachine = 4
} WNF_DATA_SCOPE, * PWNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName = 0,
	WnfPermanentStateName = 1,
	WnfPersistentStateName = 2,
	WnfTemporaryStateName = 3
} WNF_STATE_NAME_LIFETIME, * PWNF_STATE_NAME_LIFETIME;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS, * PVIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _IO_SESSION_EVENT
{
	IoSessionEventIgnore,
	IoSessionEventCreated,
	IoSessionEventTerminated,
	IoSessionEventConnected,
	IoSessionEventDisconnected,
	IoSessionEventLogon,
	IoSessionEventLogoff,
	IoSessionEventMax
} IO_SESSION_EVENT, * PIO_SESSION_EVENT;

typedef enum _PORT_INFORMATION_CLASS
{
	PortBasicInformation,
#if DEVL
	PortDumpInformation
#endif
} PORT_INFORMATION_CLASS, * PPORT_INFORMATION_CLASS;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
	PlugPlayControlEnumerateDevice,
	PlugPlayControlRegisterNewDevice,
	PlugPlayControlDeregisterDevice,
	PlugPlayControlInitializeDevice,
	PlugPlayControlStartDevice,
	PlugPlayControlUnlockDevice,
	PlugPlayControlQueryAndRemoveDevice,
	PlugPlayControlUserResponse,
	PlugPlayControlGenerateLegacyDevice,
	PlugPlayControlGetInterfaceDeviceList,
	PlugPlayControlProperty,
	PlugPlayControlDeviceClassAssociation,
	PlugPlayControlGetRelatedDevice,
	PlugPlayControlGetInterfaceDeviceAlias,
	PlugPlayControlDeviceStatus,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlQueryDeviceRelations,
	PlugPlayControlTargetDeviceRelation,
	PlugPlayControlQueryConflictList,
	PlugPlayControlRetrieveDock,
	PlugPlayControlResetDevice,
	PlugPlayControlHaltDevice,
	PlugPlayControlGetBlockedDriverList,
	MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, * PPLUGPLAY_CONTROL_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, * PIO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, * PDEBUGOBJECTINFOCLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, * PSEMAPHORE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _VDMSERVICECLASS
{
	VdmStartExecution,
	VdmQueueInterrupt,
	VdmDelayInterrupt,
	VdmInitialize,
	VdmFeatures,
	VdmSetInt21Handler,
	VdmQueryDir,
	VdmPrinterDirectIoOpen,
	VdmPrinterDirectIoClose,
	VdmPrinterInitialize,
	VdmSetLdtEntries,
	VdmSetProcessLdtInfo,
	VdmAdlibEmulation,
	VdmPMCliControl,
	VdmQueryVdmProcess
} VDMSERVICECLASS, * PVDMSERVICECLASS;

#pragma warning (disable : 4201)
typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR  WriteOutputOnExit : 1;
					UCHAR  DetectManifest : 1;
					UCHAR  IFEOSkipDebugger : 1;
					UCHAR  IFEODoNotPropagateKeyState : 1;
					UCHAR  SpareBits1 : 4;
					UCHAR  SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;
		// PsCreateFailOnSectionCreate
		struct {
			HANDLE FileHandle;
		} FailSection;
		// PsCreateFailExeFormat
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;
		// PsCreateFailExeName
		struct {
			HANDLE IFEOKey;
		} ExeName;
		// PsCreateSuccess
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR  ProtectedProcess : 1;
					UCHAR  AddressSpaceOverride : 1;
					UCHAR  DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR  ManifestDetected : 1;
					UCHAR  ProtectedProcessLight : 1;
					UCHAR  SpareBits1 : 3;
					UCHAR  SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE    FileHandle;
			HANDLE    SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG     UserProcessParametersWow64;
			ULONG     CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG     PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG     ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE, * PMEMORY_RESERVE_TYPE;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
	AlpcBasicInformation,
	AlpcPortInformation,
	AlpcAssociateCompletionPortInformation,
	AlpcConnectedSIDInformation,
	AlpcServerInformation,
	AlpcMessageZoneInformation,
	AlpcRegisterCompletionListInformation,
	AlpcUnregisterCompletionListInformation,
	AlpcAdjustCompletionListConcurrencyCountInformation,
	AlpcRegisterCallbackInformation,
	AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS, * PALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
	PVOID PortContext;
	PVOID MessageContext;
	ULONG SequenceNumber;
	ULONG MessageID;
	ULONG CallbackID;
} ALPC_CONTEXT_ATTR, * PALPC_CONTEXT_ATTR;

typedef struct _ALPC_DATA_VIEW_ATTR
{
	ULONG  Flags;
	HANDLE SectionHandle;
	PVOID  ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, * PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_SECURITY_ATTR
{
	ULONG                        Flags;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	HANDLE                       ContextHandle;
	ULONG                        Reserved1;
	ULONG                        Reserved2;
} ALPC_SECURITY_ATTR, * PALPC_SECURITY_ATTR;

typedef PVOID* PPVOID;

typedef enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24,
} KPROFILE_SOURCE, * PKPROFILE_SOURCE;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
	AlpcMessageSidInformation,
	AlpcMessageTokenModifiedIdInformation
} ALPC_MESSAGE_INFORMATION_CLASS, * PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout,
	WorkerFactoryRetryTimeout,
	WorkerFactoryIdleTimeout,
	WorkerFactoryBindingCount,
	WorkerFactoryThreadMinimum,
	WorkerFactoryThreadMaximum,
	WorkerFactoryPaused,
	WorkerFactoryBasicInformation,
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation,
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
	SystemMemoryPartitionInformation,
	SystemMemoryPartitionMoveMemory,
	SystemMemoryPartitionAddPagefile,
	SystemMemoryPartitionCombineMemory,
	SystemMemoryPartitionInitialAddMemory,
	SystemMemoryPartitionGetMemoryEvents,
	SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS, * PMEMORY_PARTITION_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation,
	MutantOwnerInformation
} MUTANT_INFORMATION_CLASS, * PMUTANT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS, * PATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
	IN PVOID TimerContext,
	IN ULONG TimerLowValue,
	IN LONG TimerHighValue);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef LANGID* PLANGID;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS
{
	DirectoryNotifyInformation = 1,
	DirectoryNotifyExtendedInformation = 2,
} DIRECTORY_NOTIFY_INFORMATION_CLASS, * PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS, * PEVENT_INFORMATION_CLASS;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	unsigned long AllocatedAttributes;
	unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG                       Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T                      MaxMessageLength;
	SIZE_T                      MemoryBandwidth;
	SIZE_T                      MaxPoolUsage;
	SIZE_T                      MaxSectionSize;
	SIZE_T                      MaxViewSize;
	SIZE_T                      MaxTotalSectionSize;
	ULONG                       DupObjectTypes;
#ifdef _WIN64
	ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef enum _IO_SESSION_STATE
{
	IoSessionStateCreated = 1,
	IoSessionStateInitialized = 2,
	IoSessionStateConnected = 3,
	IoSessionStateDisconnected = 4,
	IoSessionStateDisconnectedLoggedOn = 5,
	IoSessionStateLoggedOn = 6,
	IoSessionStateLoggedOff = 7,
	IoSessionStateTerminated = 8,
	IoSessionStateMax = 9,
} IO_SESSION_STATE, * PIO_SESSION_STATE;

typedef const WNF_STATE_NAME* PCWNF_STATE_NAME;

typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;

typedef struct _WNF_DELIVERY_DESCRIPTOR
{
	unsigned __int64 SubscriptionId;
	WNF_STATE_NAME   StateName;
	unsigned long    ChangeStamp;
	unsigned long    StateDataSize;
	unsigned long    EventMask;
	WNF_TYPE_ID      TypeId;
	unsigned long    StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, * PWNF_DELIVERY_DESCRIPTOR;

typedef enum _DEBUG_CONTROL_CODE
{
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracePoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31
} DEBUG_CONTROL_CODE, * PDEBUG_CONTROL_CODE;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _PORT_MESSAGE
{
	union
	{
		union
		{
			struct
			{
				short DataLength;
				short TotalLength;
			} s1;
			unsigned long Length;
		};
	} u1;
	union
	{
		union
		{
			struct
			{
				short Type;
				short DataInfoOffset;
			} s2;
			unsigned long ZeroInit;
		};
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double    DoNotUseThisField;
	};
	unsigned long MessageId;
	union
	{
		unsigned __int64 ClientViewSize;
		struct
		{
			unsigned long CallbackId;
			long          __PADDING__[1];
		};
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

#pragma warning (default: 4201)

typedef struct _FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef struct _PORT_SECTION_READ
{
	ULONG Length;
	ULONG ViewSize;
	ULONG ViewBase;
} PORT_SECTION_READ, * PPORT_SECTION_READ;

typedef struct _PORT_SECTION_WRITE
{
	ULONG  Length;
	HANDLE SectionHandle;
	ULONG  SectionOffset;
	ULONG  ViewSize;
	PVOID  ViewBase;
	PVOID  TargetViewBase;
} PORT_SECTION_WRITE, * PPORT_SECTION_WRITE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE, * PTIMER_TYPE;

typedef struct _BOOT_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, * PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, * PEFI_DRIVER_ENTRY;

typedef USHORT RTL_ATOM, * PRTL_ATOM;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
	TimerSetCoalescableTimer,
	MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS, * PTIMER_SET_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsVolumeFlagsInformation = 10,
	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMetadataSizeInformation = 13,
	FileFsFullSizeInformationEx = 14,
	FileFsMaximumInformation = 15,
} FSINFOCLASS, * PFSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, * PWAIT_TYPE;

typedef struct _USER_STACK
{
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, * PUSER_STACK;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;

typedef enum _APPHELPCACHESERVICECLASS
{
	ApphelpCacheServiceLookup = 0,
	ApphelpCacheServiceRemove = 1,
	ApphelpCacheServiceUpdate = 2,
	ApphelpCacheServiceFlush = 3,
	ApphelpCacheServiceDump = 4,
	ApphelpDBGReadRegistry = 0x100,
	ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, * PAPPHELPCACHESERVICECLASS;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID           KeyContext;
	PVOID           ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
	ThreadTimes, // q: KERNEL_USER_TIMES
	ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
	ThreadBasePriority, // s: KPRIORITY
	ThreadAffinityMask, // s: KAFFINITY
	ThreadImpersonationToken, // s: HANDLE
	ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
	ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
	ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
	ThreadPerformanceCount, // q: LARGE_INTEGER
	ThreadAmILastThread, // q: ULONG
	ThreadIdealProcessor, // s: ULONG
	ThreadPriorityBoost, // qs: ULONG
	ThreadSetTlsArrayAddress, // s: ULONG_PTR // Obsolete
	ThreadIsIoPending, // q: ULONG
	ThreadHideFromDebugger, // q: BOOLEAN; s: void
	ThreadBreakOnTermination, // qs: ULONG
	ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
	ThreadIsTerminated, // q: ULONG // 20
	ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
	ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
	ThreadPagePriority, // qs: PAGE_PRIORITY_INFORMATION
	ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
	ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
	ThreadCSwitchMon, // Obsolete
	ThreadCSwitchPmu,
	ThreadWow64Context, // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
	ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
	ThreadUmsInformation, // q: THREAD_UMS_INFORMATION // Obsolete
	ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
	ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
	ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
	ThreadSuspendCount, // q: ULONG // since WINBLUE
	ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
	ThreadContainerId, // q: GUID
	ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
	ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
	ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
	ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
	ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
	ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
	ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
	ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
	ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
	ThreadCreateStateChange, // since WIN11
	ThreadApplyStateChange,
	ThreadStrongerBadHandleChecks, // since 22H1
	ThreadEffectiveIoPriority, // q: IO_PRIORITY_HINT
	ThreadEffectivePagePriority, // q: ULONG
	ThreadUpdateLockOwnership, // since 24H2
	ThreadSchedulerSharedDataSlot, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION
	ThreadTebInformationAtomic, // THREAD_TEB_INFORMATION
	ThreadIndexInformation, // THREAD_INDEX_INFORMATION
	MaxThreadInfoClass
} THREADINFOCLASS;

typedef LONG KPRIORITY, * PKPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; 
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_TYPES_INFORMATION {
	ULONG NumberOfObjectTypes;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_TYPES_INFORMATION, * POBJECT_ALL_TYPES_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION {
	ULONG NumberOfObjects;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation, // q: OBJECT_BASIC_INFORMATION
	ObjectNameInformation, // q: OBJECT_NAME_INFORMATION
	ObjectTypeInformation, // q: OBJECT_TYPE_INFORMATION
	ObjectTypesInformation, // q: OBJECT_TYPES_INFORMATION
	ObjectHandleFlagInformation, // qs: OBJECT_HANDLE_FLAG_INFORMATION
	ObjectSessionInformation, // s: void // change object session // (requires SeTcbPrivilege)
	ObjectSessionObjectInformation, // s: void // change object session // (requires SeTcbPrivilege)
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS, * PKEY_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS, * PTIMER_INFORMATION_CLASS;

typedef struct _KCONTINUE_ARGUMENT
{
	KCONTINUE_TYPE ContinueType;
	ULONG          ContinueFlags;
	ULONGLONG      Reserved[2];
} KCONTINUE_ARGUMENT, * PKCONTINUE_ARGUMENT;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PDbg_PEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;                  // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
	ULONG NumberOfThreads;                  // The NumberOfThreads member contains the number of threads in the process.
	ULONGLONG WorkingSetPrivateSize;        // The total private memory that a process currently has allocated and is physically resident in memory. // since VISTA
	ULONG HardFaultCount;                   // The total number of hard faults for data from disk rather than from in-memory pages. // since WIN7
	ULONG NumberOfThreadsHighWatermark;     // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
	ULONGLONG CycleTime;                    // The sum of the cycle time of all threads in the process.
	LARGE_INTEGER CreateTime;               // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
	LARGE_INTEGER UserTime;                 // Number of 100-nanosecond intervals the process has executed in user mode.
	LARGE_INTEGER KernelTime;               // Number of 100-nanosecond intervals the process has executed in kernel mode.
	UNICODE_STRING ImageName;               // The file name of the executable image.
	KPRIORITY BasePriority;                 // The starting priority of the process.
	HANDLE UniqueProcessId;                 // The identifier of the process.
	HANDLE InheritedFromUniqueProcessId;    // The identifier of the process that created this process. Not updated and incorrectly refers to processes with recycled identifiers. 
	ULONG HandleCount;                      // The current number of open handles used by the process.
	ULONG SessionId;                        // The identifier of the Remote Desktop Services session under which the specified process is running. 
	ULONG_PTR UniqueProcessKey;             // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;                 // The peak size, in bytes, of the virtual memory used by the process.
	SIZE_T VirtualSize;                     // The current size, in bytes, of virtual memory used by the process.
	ULONG PageFaultCount;                   // The total number of page faults for data that is not currently in memory. The value wraps around to zero on average 24 hours.
	SIZE_T PeakWorkingSetSize;              // The peak size, in kilobytes, of the working set of the process.
	SIZE_T WorkingSetSize;                  // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
	SIZE_T QuotaPeakPagedPoolUsage;         // The peak quota charged to the process for pool usage, in bytes.
	SIZE_T QuotaPagedPoolUsage;             // The quota charged to the process for paged pool usage, in bytes.
	SIZE_T QuotaPeakNonPagedPoolUsage;      // The peak quota charged to the process for nonpaged pool usage, in bytes.
	SIZE_T QuotaNonPagedPoolUsage;          // The current quota charged to the process for nonpaged pool usage.
	SIZE_T PagefileUsage;                   // The total number of bytes of page file storage in use by the process.
	SIZE_T PeakPagefileUsage;               // The maximum number of bytes of page-file storage used by the process.
	SIZE_T PrivatePageCount;                // The number of memory pages allocated for the use by the process.
	LARGE_INTEGER ReadOperationCount;       // The total number of read operations performed.
	LARGE_INTEGER WriteOperationCount;      // The total number of write operations performed.
	LARGE_INTEGER OtherOperationCount;      // The total number of I/O operations performed other than read and write operations.
	LARGE_INTEGER ReadTransferCount;        // The total number of bytes read during a read operation.
	LARGE_INTEGER WriteTransferCount;       // The total number of bytes written during a write operation.
	LARGE_INTEGER OtherTransferCount;       // The total number of bytes transferred during operations other than read and write operations.
	// SYSTEM_THREAD_INFORMATION Threads[1];   // This type is not defined in the structure but was added for convenience.
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

/*
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	_Field_size_(NumberOfHandles) SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
*/
typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SEGMENT_HEAP
{
	ULONG_PTR Padding[2];
	ULONG Signature;
	ULONG GlobalFlags;
	// ...
} SEGMENT_HEAP, PSEGMENT_HEAP;

#define WOW64_POINTER(Type) ULONG

typedef struct _HEAP_ENTRY32
{
	WOW64_POINTER(PVOID) Data1;
	WOW64_POINTER(PVOID) Data2;
} HEAP_ENTRY32, * PHEAP_ENTRY32;

typedef struct _HEAP_SEGMENT32
{
	HEAP_ENTRY32 HeapEntry;
	ULONG SegmentSignature;
	ULONG SegmentFlags;
	LIST_ENTRY32 SegmentListEntry;
	WOW64_POINTER(struct _HEAP32*) Heap;
	WOW64_POINTER(PVOID) BaseAddress;
	ULONG NumberOfPages;
	WOW64_POINTER(PHEAP_ENTRY32) FirstEntry;
	WOW64_POINTER(PHEAP_ENTRY32) LastValidEntry;
	ULONG NumberOfUnCommittedPages;
	ULONG NumberOfUnCommittedRanges;
	USHORT SegmentAllocatorBackTraceIndex;
	USHORT Reserved;
	LIST_ENTRY32 UCRSegmentList;
} HEAP_SEGMENT32, * PHEAP_SEGMENT32;

#define HEAP_SEGMENT_SIGNATURE 0xffeeffee
#define HEAP_SIGNATURE 0xeeffeeff
#define SEGMENT_HEAP_SIGNATURE 0xddeeddee
#define HEAP_SEGMENT_MAX_SIZE \
    (max(sizeof(HEAP_SEGMENT), sizeof(HEAP_SEGMENT32)))

typedef struct _RTL_HEAP_ENTRY
{
	SIZE_T Size;
	USHORT Flags;
	USHORT AllocatorBackTraceIndex;
	union
	{
		struct
		{
			SIZE_T Settable;
			ULONG Tag;
		} s1;
		struct
		{
			SIZE_T CommittedSize;
			PVOID FirstBlock;
		} s2;
	} u;
} RTL_HEAP_ENTRY, * PRTL_HEAP_ENTRY;

typedef struct _RTL_HEAP_TAG
{
	ULONG NumberOfAllocations;
	ULONG NumberOfFrees;
	SIZE_T BytesAllocated;
	USHORT TagIndex;
	USHORT CreatorBackTraceIndex;
	WCHAR TagName[24];
} RTL_HEAP_TAG, * PRTL_HEAP_TAG;

// Windows 7/8/10
typedef struct _RTL_HEAP_INFORMATION_V1
{
	PVOID BaseAddress;
	ULONG Flags;
	USHORT EntryOverhead;
	USHORT CreatorBackTraceIndex;
	SIZE_T BytesAllocated;
	SIZE_T BytesCommitted;
	ULONG NumberOfTags;
	ULONG NumberOfEntries;
	ULONG NumberOfPseudoTags;
	ULONG PseudoTagGranularity;
	ULONG Reserved[5];
	PRTL_HEAP_TAG Tags;
	PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION_V1, * PRTL_HEAP_INFORMATION_V1;

// Windows 11 > 22000
typedef struct _RTL_HEAP_INFORMATION_V2
{
	PVOID BaseAddress;
	ULONG Flags;
	USHORT EntryOverhead;
	USHORT CreatorBackTraceIndex;
	SIZE_T BytesAllocated;
	SIZE_T BytesCommitted;
	ULONG NumberOfTags;
	ULONG NumberOfEntries;
	ULONG NumberOfPseudoTags;
	ULONG PseudoTagGranularity;
	ULONG Reserved[5];
	PRTL_HEAP_TAG Tags;
	PRTL_HEAP_ENTRY Entries;
	ULONG64 HeapTag;
} RTL_HEAP_INFORMATION_V2, * PRTL_HEAP_INFORMATION_V2;

typedef struct _HEAP_ENTRY {
	PVOID Data1;
	PVOID Data2;
} HEAP_ENTRY, * PHEAP_ENTRY;

typedef struct _HEAP_SEGMENT {
	HEAP_ENTRY Entry;
	ULONG SegmentSignature;
	ULONG SegmentFlags;
	LIST_ENTRY SegmentListEntry;
	struct _HEAP* Heap;
	PVOID BaseAddress;
	ULONG NumberOfPages;
	PHEAP_ENTRY FirstEntry;
	PHEAP_ENTRY LastValidEntry;
	ULONG NumberOfUnCommittedPages;
	ULONG NumberOfUnCommittedRanges;
	USHORT SegmentAllocatorBackTraceIndex;
	USHORT Reserved;
	LIST_ENTRY UCRSegmentList;
} HEAP_SEGMENT, * PHEAP_SEGMENT;

typedef struct _HEAP {
	HEAP_SEGMENT Segment;
	ULONG Flags;
	ULONG ForceFlags;
	ULONG CompatibilityFlags;
	ULONG EncodeFlagMask;
	HEAP_ENTRY Encoding;
	ULONG Interceptor;
	ULONG VirtualMemoryThreshold;
	ULONG Signature;
} HEAP, * PHEAP;

// HEAP_INFORMATION_CLASS
#define HeapCompatibilityInformation 0x0 // q; s: ULONG
#define HeapEnableTerminationOnCorruption 0x1 // q; s: NULL
#define HeapExtendedInformation 0x2 // q; s: HEAP_EXTENDED_INFORMATION
#define HeapOptimizeResources 0x3 // q; s: HEAP_OPTIMIZE_RESOURCES_INFORMATION
#define HeapTaggingInformation 0x4
#define HeapStackDatabase 0x5 // q: RTL_HEAP_STACK_QUERY; s: RTL_HEAP_STACK_CONTROL
#define HeapMemoryLimit 0x6 // since 19H2
#define HeapTag 0x7 // since 20H1
#define HeapDetailedFailureInformation 0x80000001
#define HeapSetDebuggingInformation 0x80000002 // q; s: HEAP_DEBUGGING_INFORMATION

typedef enum _HEAP_COMPATIBILITY_MODE
{
	HEAP_COMPATIBILITY_STANDARD = 0UL,
	HEAP_COMPATIBILITY_LAL = 1UL,
	HEAP_COMPATIBILITY_LFH = 2UL,
} HEAP_COMPATIBILITY_MODE;

typedef struct _RTLP_TAG_INFO
{
	GUID Id;
	ULONG_PTR CurrentAllocatedBytes;
} RTLP_TAG_INFO, * PRTLP_TAG_INFO;

typedef struct _RTLP_HEAP_TAGGING_INFO
{
	USHORT Version;
	USHORT Flags;
	PVOID ProcessHandle;
	ULONG_PTR EntriesCount;
	RTLP_TAG_INFO Entries[1];
} RTLP_HEAP_TAGGING_INFO, * PRTLP_HEAP_TAGGING_INFO;

typedef struct _PROCESS_HEAP_INFORMATION
{
	SIZE_T ReserveSize;
	SIZE_T CommitSize;
	ULONG NumberOfHeaps;
	ULONG_PTR FirstHeapInformationOffset;
} PROCESS_HEAP_INFORMATION, * PPROCESS_HEAP_INFORMATION;

typedef struct _HEAP_REGION_INFORMATION
{
	PVOID Address;
	SIZE_T ReserveSize;
	SIZE_T CommitSize;
	ULONG_PTR FirstRangeInformationOffset;
	ULONG_PTR NextRegionInformationOffset;
} HEAP_REGION_INFORMATION, * PHEAP_REGION_INFORMATION;

typedef struct _HEAP_RANGE_INFORMATION
{
	PVOID Address;
	SIZE_T Size;
	ULONG Type;
	ULONG Protection;
	ULONG_PTR FirstBlockInformationOffset;
	ULONG_PTR NextRangeInformationOffset;
} HEAP_RANGE_INFORMATION, * PHEAP_RANGE_INFORMATION;

typedef struct _HEAP_BLOCK_INFORMATION
{
	PVOID Address;
	ULONG Flags;
	SIZE_T DataSize;
	ULONG_PTR OverheadSize;
	ULONG_PTR NextBlockInformationOffset;
} HEAP_BLOCK_INFORMATION, * PHEAP_BLOCK_INFORMATION;

typedef struct _HEAP_INFORMATION
{
	PVOID Address;
	ULONG Mode;
	SIZE_T ReserveSize;
	SIZE_T CommitSize;
	ULONG_PTR FirstRegionInformationOffset;
	ULONG_PTR NextHeapInformationOffset;
} HEAP_INFORMATION, * PHEAP_INFORMATION;

typedef struct _SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION
{
	SIZE_T SegmentReserveSize;
	SIZE_T SegmentCommitSize;
	ULONG_PTR SegmentCount;
	SIZE_T AllocatedSize;
	SIZE_T LargeAllocReserveSize;
	SIZE_T LargeAllocCommitSize;
} SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION, * PSEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION;

#define HeapPerformanceCountersInformationStandardHeapVersion 0x1
#define HeapPerformanceCountersInformationSegmentHeapVersion 0x2

typedef struct _HEAP_PERFORMANCE_COUNTERS_INFORMATION
{
	ULONG Size;
	ULONG Version;
	ULONG HeapIndex;
	ULONG LastHeapIndex;
	PVOID BaseAddress;
	SIZE_T ReserveSize;
	SIZE_T CommitSize;
	ULONG SegmentCount;
	SIZE_T LargeUCRMemory;
	ULONG UCRLength;
	SIZE_T AllocatedSpace;
	SIZE_T FreeSpace;
	ULONG FreeListLength;
	ULONG Contention;
	ULONG VirtualBlocks;
	ULONG CommitRate;
	ULONG DecommitRate;
	SEGMENT_HEAP_PERFORMANCE_COUNTER_INFORMATION SegmentHeapPerfInformation; // since WIN8
} HEAP_PERFORMANCE_COUNTERS_INFORMATION, * PHEAP_PERFORMANCE_COUNTERS_INFORMATION;

typedef struct _HEAP_INFORMATION_ITEM
{
	ULONG Level;
	SIZE_T Size;
	union
	{
		PROCESS_HEAP_INFORMATION ProcessHeapInformation;
		HEAP_INFORMATION HeapInformation;
		HEAP_REGION_INFORMATION HeapRegionInformation;
		HEAP_RANGE_INFORMATION HeapRangeInformation;
		HEAP_BLOCK_INFORMATION HeapBlockInformation;
		HEAP_PERFORMANCE_COUNTERS_INFORMATION HeapPerfInformation;
		ULONG_PTR DynamicStart;
	};
} HEAP_INFORMATION_ITEM, * PHEAP_INFORMATION_ITEM;

typedef NTSTATUS(NTAPI* PRTL_HEAP_EXTENDED_ENUMERATION_ROUTINE)(
	_In_ PHEAP_INFORMATION_ITEM Information,
	_In_opt_ PVOID Context
	);

#define HeapExtendedProcessHeapInformationLevel 0x1
#define HeapExtendedHeapInformationLevel 0x2
#define HeapExtendedHeapRegionInformationLevel 0x3
#define HeapExtendedHeapRangeInformationLevel 0x4
#define HeapExtendedHeapBlockInformationLevel 0x5
#define HeapExtendedHeapHeapPerfInformationLevel 0x80000000

typedef struct _HEAP_EXTENDED_INFORMATION
{
	HANDLE ProcessHandle;
	PVOID HeapHandle;
	ULONG Level;
	PRTL_HEAP_EXTENDED_ENUMERATION_ROUTINE CallbackRoutine;
	PVOID CallbackContext;
	union
	{
		PROCESS_HEAP_INFORMATION ProcessHeapInformation;
		HEAP_INFORMATION HeapInformation;
	};
} HEAP_EXTENDED_INFORMATION, * PHEAP_EXTENDED_INFORMATION;

typedef NTSTATUS(NTAPI* RTL_HEAP_STACK_WRITE_ROUTINE)(
	_In_ PVOID Information,
	_In_ ULONG Size,
	_In_opt_ PVOID Context
	);

typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_INIT
{
	ULONG Count;
	ULONG Total;
	ULONG Flags;
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_INIT, * PRTLP_HEAP_STACK_TRACE_SERIALIZATION_INIT;

typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_HEADER
{
	USHORT Version;
	USHORT PointerSize;
	PVOID Heap;
	SIZE_T TotalCommit;
	SIZE_T TotalReserve;
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_HEADER, * PRTLP_HEAP_STACK_TRACE_SERIALIZATION_HEADER;

typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_ALLOCATION
{
	PVOID Address;
	ULONG Flags;
	SIZE_T DataSize;
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_ALLOCATION, * PRTLP_HEAP_STACK_TRACE_SERIALIZATION_ALLOCATION;

typedef struct _RTLP_HEAP_STACK_TRACE_SERIALIZATION_STACKFRAME
{
	PVOID StackFrame[8];
} RTLP_HEAP_STACK_TRACE_SERIALIZATION_STACKFRAME, * PRTLP_HEAP_STACK_TRACE_SERIALIZATION_STACKFRAME;

#define HEAP_STACK_QUERY_VERSION 0x2

typedef struct _RTL_HEAP_STACK_QUERY
{
	ULONG Version;
	HANDLE ProcessHandle;
	RTL_HEAP_STACK_WRITE_ROUTINE WriteRoutine;
	PVOID SerializationContext;
	UCHAR QueryLevel;
	UCHAR Flags;
} RTL_HEAP_STACK_QUERY, * PRTL_HEAP_STACK_QUERY;

#define HEAP_STACK_CONTROL_VERSION 0x1
#define HEAP_STACK_CONTROL_FLAGS_STACKTRACE_ENABLE 0x1
#define HEAP_STACK_CONTROL_FLAGS_STACKTRACE_DISABLE 0x2

typedef struct _RTL_HEAP_STACK_CONTROL
{
	USHORT Version;
	USHORT Flags;
	HANDLE ProcessHandle;
} RTL_HEAP_STACK_CONTROL, * PRTL_HEAP_STACK_CONTROL;

typedef NTSTATUS(NTAPI* PRTL_HEAP_DEBUGGING_INTERCEPTOR_ROUTINE)(
	_In_ PVOID HeapHandle,
	_In_ ULONG Action,
	_In_ ULONG StackFramesToCapture,
	_In_ PVOID* StackTrace
	);

typedef NTSTATUS(NTAPI* PRTL_HEAP_LEAK_ENUMERATION_ROUTINE)(
	_In_ LONG Reserved,
	_In_ PVOID HeapHandle,
	_In_ PVOID BaseAddress,
	_In_ SIZE_T BlockSize,
	_In_ ULONG StackTraceDepth,
	_In_ PVOID* StackTrace
	);

typedef struct _HEAP_DEBUGGING_INFORMATION
{
	PRTL_HEAP_DEBUGGING_INTERCEPTOR_ROUTINE InterceptorFunction;
	USHORT InterceptorValue;
	ULONG ExtendedOptions;
	ULONG StackTraceDepth;
	SIZE_T MinTotalBlockSize;
	SIZE_T MaxTotalBlockSize;
	PRTL_HEAP_LEAK_ENUMERATION_ROUTINE HeapLeakEnumerationRoutine;
} HEAP_DEBUGGING_INFORMATION, * PHEAP_DEBUGGING_INFORMATION;

typedef struct _RTL_PROCESS_MODULES* PRTL_PROCESS_MODULES;
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX* PRTL_PROCESS_MODULE_INFORMATION_EX;
typedef struct _RTL_PROCESS_BACKTRACES* PRTL_PROCESS_BACKTRACES;
typedef struct _RTL_PROCESS_LOCKS* PRTL_PROCESS_LOCKS;

typedef struct _RTL_PROCESS_VERIFIER_OPTIONS
{
	ULONG SizeStruct;
	ULONG Option;
	UCHAR OptionData[1];
} RTL_PROCESS_VERIFIER_OPTIONS, * PRTL_PROCESS_VERIFIER_OPTIONS;

typedef struct _RTL_DEBUG_INFORMATION
{
	HANDLE SectionHandleClient;
	PVOID ViewBaseClient;
	PVOID ViewBaseTarget;
	ULONG_PTR ViewBaseDelta;
	HANDLE EventPairClient;
	HANDLE EventPairTarget;
	HANDLE TargetProcessId;
	HANDLE TargetThreadHandle;
	ULONG Flags;
	SIZE_T OffsetFree;
	SIZE_T CommitSize;
	SIZE_T ViewSize;
	union
	{
		PRTL_PROCESS_MODULES Modules;
		PRTL_PROCESS_MODULE_INFORMATION_EX ModulesEx;
	};
	PRTL_PROCESS_BACKTRACES BackTraces;
	PVOID Heaps;
	PRTL_PROCESS_LOCKS Locks;
	PVOID SpecificHeap;
	HANDLE TargetProcessHandle;
	PRTL_PROCESS_VERIFIER_OPTIONS VerifierOptions;
	PVOID ProcessHeap;
	HANDLE CriticalSectionHandle;
	HANDLE CriticalSectionOwnerThread;
	PVOID Reserved[4];
} RTL_DEBUG_INFORMATION, * PRTL_DEBUG_INFORMATION;

#define RTL_QUERY_PROCESS_MODULES 0x00000001
#define RTL_QUERY_PROCESS_BACKTRACES 0x00000002
#define RTL_QUERY_PROCESS_HEAP_SUMMARY 0x00000004
#define RTL_QUERY_PROCESS_HEAP_TAGS 0x00000008
#define RTL_QUERY_PROCESS_HEAP_ENTRIES 0x00000010
#define RTL_QUERY_PROCESS_LOCKS 0x00000020
#define RTL_QUERY_PROCESS_MODULES32 0x00000040
#define RTL_QUERY_PROCESS_VERIFIER_OPTIONS 0x00000080 // rev
#define RTL_QUERY_PROCESS_MODULESEX 0x00000100 // rev
#define RTL_QUERY_PROCESS_HEAP_SEGMENTS 0x00000200
#define RTL_QUERY_PROCESS_CS_OWNER 0x00000400 // rev
#define RTL_QUERY_PROCESS_NONINVASIVE 0x80000000
#define RTL_QUERY_PROCESS_NONINVASIVE_CS_OWNER 0x80000800 // WIN11

typedef struct _RTL_PROCESS_HEAPS_V1
{
	ULONG NumberOfHeaps;
	_Field_size_(NumberOfHeaps) RTL_HEAP_INFORMATION_V1 Heaps[1];
} RTL_PROCESS_HEAPS_V1, * PRTL_PROCESS_HEAPS_V1;

typedef struct _RTL_PROCESS_HEAPS_V2
{
	ULONG NumberOfHeaps;
	_Field_size_(NumberOfHeaps) RTL_HEAP_INFORMATION_V2 Heaps[1];
} RTL_PROCESS_HEAPS_V2, * PRTL_PROCESS_HEAPS_V2;

#define RTL_HEAP_BUSY (USHORT)0x0001
#define RTL_HEAP_SEGMENT (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1 (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2 (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3 (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS (USHORT)0x00e0
#define RTL_HEAP_UNCOMMITTED_RANGE (USHORT)0x1000
#define RTL_HEAP_PROTECTED_ENTRY (USHORT)0x2000
#define RTL_HEAP_LARGE_ALLOC (USHORT)0x4000
#define RTL_HEAP_LFH_ALLOC (USHORT)0x8000

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define GENERIC_EXECUTE                  (0x20000000L)
#define GENERIC_ALL                      (0x10000000L)

#define FILE_SHARE_READ                 0x00000001  
#define FILE_SHARE_WRITE                0x00000002  
#define FILE_SHARE_DELETE               0x00000004  
#define FILE_ATTRIBUTE_READONLY             0x00000001  
#define FILE_ATTRIBUTE_HIDDEN               0x00000002  
#define FILE_ATTRIBUTE_SYSTEM               0x00000004  
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010  
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020  
#define FILE_ATTRIBUTE_DEVICE               0x00000040  
#define FILE_ATTRIBUTE_NORMAL               0x00000080  
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100  
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200  
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400  
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800  
#define FILE_ATTRIBUTE_OFFLINE              0x00001000  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000  
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000  
#define FILE_ATTRIBUTE_INTEGRITY_STREAM     0x00008000  
#define FILE_ATTRIBUTE_VIRTUAL              0x00010000  
#define FILE_ATTRIBUTE_NO_SCRUB_DATA        0x00020000  
#define FILE_ATTRIBUTE_EA                   0x00040000  
#define FILE_ATTRIBUTE_PINNED               0x00080000  
#define FILE_ATTRIBUTE_UNPINNED             0x00100000  
#define FILE_ATTRIBUTE_RECALL_ON_OPEN       0x00040000  
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x00400000 
#define TREE_CONNECT_ATTRIBUTE_PRIVACY      0x00004000  
#define TREE_CONNECT_ATTRIBUTE_INTEGRITY    0x00008000  
#define TREE_CONNECT_ATTRIBUTE_GLOBAL       0x00000004  
#define TREE_CONNECT_ATTRIBUTE_PINNED       0x00000002  
#define FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL  0x20000000  
#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001   
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002   
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004   
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008   
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010   
#define FILE_NOTIFY_CHANGE_LAST_ACCESS  0x00000020   
#define FILE_NOTIFY_CHANGE_CREATION     0x00000040   
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100   
#define FILE_ACTION_ADDED                   0x00000001   
#define FILE_ACTION_REMOVED                 0x00000002   
#define FILE_ACTION_MODIFIED                0x00000003   
#define FILE_ACTION_RENAMED_OLD_NAME        0x00000004   
#define FILE_ACTION_RENAMED_NEW_NAME        0x00000005   
#define MAILSLOT_NO_MESSAGE             ((DWORD)-1) 
#define MAILSLOT_WAIT_FOREVER           ((DWORD)-1) 
#define FILE_CASE_SENSITIVE_SEARCH          0x00000001  
#define FILE_CASE_PRESERVED_NAMES           0x00000002  
#define FILE_UNICODE_ON_DISK                0x00000004  
#define FILE_PERSISTENT_ACLS                0x00000008  
#define FILE_FILE_COMPRESSION               0x00000010  
#define FILE_VOLUME_QUOTAS                  0x00000020  
#define FILE_SUPPORTS_SPARSE_FILES          0x00000040  
#define FILE_SUPPORTS_REPARSE_POINTS        0x00000080  
#define FILE_SUPPORTS_REMOTE_STORAGE        0x00000100  
#define FILE_RETURNS_CLEANUP_RESULT_INFO    0x00000200  
#define FILE_SUPPORTS_POSIX_UNLINK_RENAME   0x00000400  
#define FILE_SUPPORTS_BYPASS_IO             0x00000800  
#define FILE_SUPPORTS_STREAM_SNAPSHOTS      0x00001000  
#define FILE_SUPPORTS_CASE_SENSITIVE_DIRS   0x00002000  

#define FILE_VOLUME_IS_COMPRESSED           0x00008000  
#define FILE_SUPPORTS_OBJECT_IDS            0x00010000  
#define FILE_SUPPORTS_ENCRYPTION            0x00020000  
#define FILE_NAMED_STREAMS                  0x00040000  
#define FILE_READ_ONLY_VOLUME               0x00080000  
#define FILE_SEQUENTIAL_WRITE_ONCE          0x00100000  
#define FILE_SUPPORTS_TRANSACTIONS          0x00200000  
#define FILE_SUPPORTS_HARD_LINKS            0x00400000  
#define FILE_SUPPORTS_EXTENDED_ATTRIBUTES   0x00800000  
#define FILE_SUPPORTS_OPEN_BY_FILE_ID       0x01000000  
#define FILE_SUPPORTS_USN_JOURNAL           0x02000000  
#define FILE_SUPPORTS_INTEGRITY_STREAMS     0x04000000  
#define FILE_SUPPORTS_BLOCK_REFCOUNTING     0x08000000  
#define FILE_SUPPORTS_SPARSE_VDL            0x10000000  
#define FILE_DAX_VOLUME                     0x20000000  
#define FILE_SUPPORTS_GHOSTING              0x40000000  

#define FILE_INVALID_FILE_ID               ((LONGLONG)-1LL) 
#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000
