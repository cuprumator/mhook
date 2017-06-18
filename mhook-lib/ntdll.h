#ifndef _NT_DLL_H_
#define _NT_DLL_H_

#include <windows.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

namespace Nt
{
    typedef struct _LDR_MODULE
    {
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID BaseAddress;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        SHORT LoadCount;
        SHORT TlsIndex;
        LIST_ENTRY HashTableEntry;
        ULONG TimeDateStamp;
    }
    LDR_MODULE, *PLDR_MODULE;

    typedef struct _PEB_LDR_DATA
    {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    }
    PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _RTL_USER_PROCESS_PARAMETERS
    {
        BYTE Reserved1[16];
        PVOID Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

    typedef
        VOID
        (NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (
        VOID
        );

    typedef struct _PEB
    {
        BYTE                          Reserved1[2];
        BYTE                          BeingDebugged;
        BYTE                          Reserved2[1];
        PVOID                         Reserved3[2];
        PPEB_LDR_DATA                 Ldr;
        PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
        BYTE                          Reserved4[104];
        PVOID                         Reserved5[52];
        PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
        BYTE                          Reserved6[128];
        PVOID                         Reserved7[1];
        ULONG                         SessionId;
    } PEB, *PPEB;

    typedef struct _USER_STACK
    {
        PVOID	FixedStackBase;
        PVOID	FixedStackLimit;
        PVOID	ExpandableStackBase;
        PVOID	ExpandableStackLimit;
        PVOID	ExpandableStackBottom;
    } USER_STACK, *PUSER_STACK;

    typedef LONG		KPRIORITY;

    typedef enum _KWAIT_REASON
    {
        Executive,
        FreePage,
        PageIn,
        PoolAllocation,
        DelayExecution,
        Suspended,
        UserRequest,
        WrExecutive,
        WrFreePage,
        WrPageIn,
        WrPoolAllocation,
        WrDelayExecution,
        WrSuspended,
        WrUserRequest,
        WrEventPair,
        WrQueue,
        WrLpcReceive,
        WrLpcReply,
        WrVirtualMemory,
        WrPageOut,
        WrRendezvous,
        Spare2,
        Spare3,
        Spare4,
        Spare5,
        Spare6,
        WrKernel,
        MaximumWaitReason
    } KWAIT_REASON, *PKWAIT_REASON;

    typedef enum
    {
        StateInitialized,
        StateReady,
        StateRunning,
        StateStandby,
        StateTerminated,
        StateWait,
        StateTransition,
        StateUnknown
    } THREAD_STATE;

    typedef struct _VM_COUNTERS
    {
        ULONG	uPeakVirtualSize;
        ULONG	uVirtualSize;
        ULONG	uPageFaultCount;
        ULONG	uPeakWorkingSetSize;
        ULONG	uWorkingSetSize;
        ULONG	uQuotaPeakPagedPoolUsage;
        ULONG	uQuotaPagedPoolUsage;
        ULONG	uQuotaPeakNonPagedPoolUsage;
        ULONG	uQuotaNonPagedPoolUsage;
        ULONG	uPagefileUsage;
        ULONG	uPeakPagefileUsage;
    } VM_COUNTERS, *PVM_COUNTERS;

    typedef struct _CLIENT_ID
    {
        HANDLE	UniqueProcess;
        HANDLE	UniqueThread;
    } CLIENT_ID, *PCLIENT_ID;

    //////////////////////////////////////////////////////////////////////////
    // SYSTEM_THREAD_INFORMATION and SYSTEM_PROCESS_INFORMATION are based on their definitions from Process Hacker sources
    
    typedef struct _SYSTEM_THREAD_INFORMATION
    {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        KPRIORITY Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        KWAIT_REASON WaitReason;
    } SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

    typedef struct _SYSTEM_PROCESS_INFORMATION
    {
        ULONG uNext;
        ULONG uThreadCount;
        LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
        ULONG HardFaultCount; // since WIN7
        ULONG NumberOfThreadsHighWatermark; // since WIN7
        ULONGLONG CycleTime; // since WIN7
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE uUniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SYSTEM_THREAD_INFORMATION Threads[1];
    } SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
    //////////////////////////////////////////////////////////////////////////

    typedef struct _SYSTEM_MODULE_INFORMATION { // Information Class 11
        ULONG   uNext;
        ULONG   Reserved;
        PVOID   Base;
        ULONG   Size;
        ULONG   Flags;
        USHORT  Index;
        USHORT  Unknown;
        USHORT  LoadCount;
        USHORT  ModuleNameOffset;
        CHAR    ImageName[256];
    } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

    typedef struct _THREAD_BASIC_INFORMATION
    {
        NTSTATUS    ExitStatus;
        PVOID       TebBaseAddress;
        CLIENT_ID   ClientId;
        KAFFINITY   AffinityMask;
        KPRIORITY   Priority;
        KPRIORITY   BasePriority;
    } THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

    typedef struct _PROCESS_BASIC_INFORMATION
    {
        PVOID Reserved1;
        PPEB PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

    typedef enum _FILE_INFORMATION_CLASS {
        FileDirectoryInformation                  = 1,
        FileFullDirectoryInformation,
        FileBothDirectoryInformation,
        FileBasicInformation,
        FileStandardInformation,
        FileInternalInformation,
        FileEaInformation,
        FileAccessInformation,
        FileNameInformation,
        FileRenameInformation,
        FileLinkInformation,
        FileNamesInformation,
        FileDispositionInformation,
        FilePositionInformation,
        FileFullEaInformation,
        FileModeInformation,
        FileAlignmentInformation,
        FileAllInformation,
        FileAllocationInformation,
        FileEndOfFileInformation,
        FileAlternateNameInformation,
        FileStreamInformation,
        FilePipeInformation,
        FilePipeLocalInformation,
        FilePipeRemoteInformation,
        FileMailslotQueryInformation,
        FileMailslotSetInformation,
        FileCompressionInformation,
        FileObjectIdInformation,
        FileCompletionInformation,
        FileMoveClusterInformation,
        FileQuotaInformation,
        FileReparsePointInformation,
        FileNetworkOpenInformation,
        FileAttributeTagInformation,
        FileTrackingInformation,
        FileIdBothDirectoryInformation,
        FileIdFullDirectoryInformation,
        FileValidDataLengthInformation,
        FileShortNameInformation,
        FileIoCompletionNotificationInformation,
        FileIoStatusBlockRangeInformation,
        FileIoPriorityHintInformation,
        FileSfioReserveInformation,
        FileSfioVolumeInformation,
        FileHardLinkInformation,
        FileProcessIdsUsingFileInformation,
        FileNormalizedNameInformation,
        FileNetworkPhysicalNameInformation,
        FileIdGlobalTxDirectoryInformation,
        FileIsRemoteDeviceInformation,
        FileAttributeCacheInformation,
        FileNumaNodeInformation,
        FileStandardLinkInformation,
        FileRemoteProtocolInformation,
        FileMaximumInformation 
    } FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

    typedef struct _FILE_BOTH_DIR_INFORMATION {
        ULONG         NextEntryOffset;
        ULONG         FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG         FileAttributes;
        ULONG         FileNameLength;
        ULONG         EaSize;
        CCHAR         ShortNameLength;
        WCHAR         ShortName[12];
        WCHAR         FileName[1];
    } FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

    typedef struct _FILE_DIRECTORY_INFORMATION {
        ULONG         NextEntryOffset;
        ULONG         FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG         FileAttributes;
        ULONG         FileNameLength;
        WCHAR         FileName[1];
    } FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

    typedef struct _FILE_FULL_DIR_INFORMATION {
        ULONG         NextEntryOffset;
        ULONG         FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG         FileAttributes;
        ULONG         FileNameLength;
        ULONG         EaSize;
        WCHAR         FileName[1];
    } FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

    typedef struct _FILE_NAMES_INFORMATION {
        ULONG NextEntryOffset;
        ULONG FileIndex;
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

    typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
        ULONG         NextEntryOffset;
        ULONG         FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG         FileAttributes;
        ULONG         FileNameLength;
        ULONG         EaSize;
        CCHAR         ShortNameLength;
        WCHAR         ShortName[12];
        LARGE_INTEGER FileId;
        WCHAR         FileName[1];
    } FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

    typedef struct _FILE_ID_FULL_DIR_INFORMATION {
        ULONG         NextEntryOffset;
        ULONG         FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG         FileAttributes;
        ULONG         FileNameLength;
        ULONG         EaSize;
        LARGE_INTEGER FileId;
        WCHAR         FileName[1];
    } FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

    typedef enum _KEY_VALUE_INFORMATION_CLASS
    {
        KeyValueBasicInformation            = 0,
        KeyValueFullInformation             = 1,
        KeyValuePartialInformation          = 2,
        KeyValueFullInformationAlign64      = 3,
        KeyValuePartialInformationAlign64   = 4,
        MaxKeyValueInfoClass                = 5 
    } KEY_VALUE_INFORMATION_CLASS;

    typedef struct _KEY_VALUE_BASIC_INFORMATION {
        ULONG TitleIndex;
        ULONG Type;
        ULONG NameLength;
        WCHAR Name[1];
    } KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

    typedef struct _KEY_VALUE_FULL_INFORMATION {
        ULONG TitleIndex;
        ULONG Type;
        ULONG DataOffset;
        ULONG DataLength;
        ULONG NameLength;
        WCHAR Name[1];
    } KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

    typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
        ULONG TitleIndex;
        ULONG Type;
        ULONG DataLength;
        UCHAR Data[1];
    } KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

    typedef enum _KEY_INFORMATION_CLASS
    {
        KeyBasicInformation            = 0,
        KeyNodeInformation             = 1,
        KeyFullInformation             = 2,
        KeyNameInformation             = 3,
        KeyCachedInformation           = 4,
        KeyFlagsInformation            = 5,
        KeyVirtualizationInformation   = 6,
        KeyHandleTagsInformation       = 7,
        MaxKeyInfoClass                = 8 
    } KEY_INFORMATION_CLASS;

    typedef struct _KEY_BASIC_INFORMATION {
        LARGE_INTEGER LastWriteTime;
        ULONG         TitleIndex;
        ULONG         NameLength;
        WCHAR         Name[1];
    } KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

    typedef struct _KEY_NODE_INFORMATION {
        LARGE_INTEGER LastWriteTime;
        ULONG         TitleIndex;
        ULONG         ClassOffset;
        ULONG         ClassLength;
        ULONG         NameLength;
        WCHAR         Name[1];
    } KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

    typedef struct _KEY_FULL_INFORMATION {
        LARGE_INTEGER LastWriteTime;
        ULONG         TitleIndex;
        ULONG         ClassOffset;
        ULONG         ClassLength;
        ULONG         SubKeys;
        ULONG         MaxNameLen;
        ULONG         MaxClassLen;
        ULONG         Values;
        ULONG         MaxValueNameLen;
        ULONG         MaxValueDataLen;
        WCHAR         Class[1];
    } KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

    typedef struct _KEY_NAME_INFORMATION {
        ULONG NameLength;
        WCHAR Name[1];
    } KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

    typedef struct _KEY_CACHED_INFORMATION {
        LARGE_INTEGER LastWriteTime;
        ULONG         TitleIndex;
        ULONG         SubKeys;
        ULONG         MaxNameLen;
        ULONG         Values;
        ULONG         MaxValueNameLen;
        ULONG         MaxValueDataLen;
        ULONG         NameLength;
    } KEY_CACHED_INFORMATION, *PKEY_CACHED_INFORMATION;

    #if defined(_WIN64)
    typedef ULONG SYSINF_PAGE_COUNT;
    #else
    typedef SIZE_T SYSINF_PAGE_COUNT;
    #endif

    typedef struct _SYSTEM_BASIC_INFORMATION {
        ULONG Reserved;
        ULONG TimerResolution;
        ULONG PageSize;
        SYSINF_PAGE_COUNT NumberOfPhysicalPages;
        SYSINF_PAGE_COUNT LowestPhysicalPageNumber;
        SYSINF_PAGE_COUNT HighestPhysicalPageNumber;
        ULONG AllocationGranularity;
        ULONG_PTR MinimumUserModeAddress;
        ULONG_PTR MaximumUserModeAddress;
        ULONG_PTR ActiveProcessorsAffinityMask;
        CCHAR NumberOfProcessors;
    } SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation = 0,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemProcessInformation = 5,
        SystemProcessorPerformanceInformation = 8,
        SystemHandleInformation = 16,
        SystemInterruptInformation = 23,
        SystemExceptionInformation = 33,
        SystemRegistryQuotaInformation = 37,
        SystemLookasideInformation = 45,
        SystemProcessIdInformation = 0x58
    } SYSTEM_INFORMATION_CLASS;

    typedef struct _SYSTEM_HANDLE {
        ULONG ProcessId;
        UCHAR ObjectTypeNumber;
        UCHAR Flags;  // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
        USHORT Handle;
        PVOID Object;
        ACCESS_MASK GrantedAccess;
    } SYSTEM_HANDLE, *PSYSTEM_HANDLE;

    typedef struct _SYSTEM_HANDLE_INFORMATION
    {
        ULONG HandleCount;
        SYSTEM_HANDLE Handles[1];
    } SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

    typedef enum _THREADINFOCLASS {
        ThreadBasicInformation,
        ThreadTimes,
        ThreadPriority,
        ThreadBasePriority,
        ThreadAffinityMask,
        ThreadImpersonationToken,
        ThreadDescriptorTableEntry,
        ThreadEnableAlignmentFaultFixup,
        ThreadEventPair_Reusable,
        ThreadQuerySetWin32StartAddress,
        ThreadZeroTlsCell,
        ThreadPerformanceCount,
        ThreadAmILastThread,
        ThreadIdealProcessor,
        ThreadPriorityBoost,
        ThreadSetTlsArrayAddress,   // Obsolete
        ThreadIsIoPending,
        ThreadHideFromDebugger,
        ThreadBreakOnTermination,
        ThreadSwitchLegacyState,
        ThreadIsTerminated,
        ThreadLastSystemCall,
        ThreadIoPriority,
        ThreadCycleTime,
        ThreadPagePriority,
        ThreadActualBasePriority,
        ThreadTebInformation,
        ThreadCSwitchMon,          // Obsolete
        ThreadCSwitchPmu,
        ThreadWow64Context,
        ThreadGroupInformation,
        ThreadUmsInformation,      // UMS
        ThreadCounterProfiling,
        ThreadIdealProcessorEx,
        MaxThreadInfoClass
    } THREADINFOCLASS;

    typedef enum _OBJECT_INFORMATION_CLASS {
        ObjectBasicInformation = 0,
        ObjectTypeInformation = 2
    } OBJECT_INFORMATION_CLASS;

    typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
        UNICODE_STRING TypeName;
        ULONG Reserved [22];    // reserved for internal use
    } PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

    typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
        ULONG       Attributes;
        ACCESS_MASK GrantedAccess;
        ULONG       HandleCount;
        ULONG       PointerCount;
        ULONG       Reserved[10];
    } PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;

    typedef struct _SYSTEM_PROCESS_ID_INFORMATION
    {
        HANDLE ProcessId;
        UNICODE_STRING ImageName;
    } SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION;
}

#endif //_NT_DLL_H_