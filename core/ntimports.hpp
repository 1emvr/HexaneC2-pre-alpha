#pragma once
#ifndef _HEXANE_NTIMPORTS_HPP
#define _HEXANE_NTIMPORTS_HPP
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <accctrl.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <memoryapi.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <type_traits>
#include <aclapi.h>
#include <iostream>
#include <float.h>
#include <math.h>
#include <array>
#include <cstdint>
#include <string>


typedef LONG NTSTATUS;
typedef LONG KPRIORITY;
typedef ULONG LOGICAL;
#define STATIC						static
#define PROCESSOR_FEATURE_MAX		64
#define MAX_WOW64_SHARED_ENTRIES	16
#define NT_SUCCESS(status)			((status) >= 0)

#if defined(_MSC_VER) && (_MSC_VER < 1300)
#define XSTATE_LEGACY_FLOATING_POINT        0
#define XSTATE_LEGACY_SSE                   1
#define XSTATE_GSSE                         2

#define XSTATE_MASK_LEGACY_FLOATING_POINT   (1i64 << (XSTATE_LEGACY_FLOATING_POINT))
#define XSTATE_MASK_LEGACY_SSE              (1i64 << (XSTATE_LEGACY_SSE))
#define XSTATE_MASK_LEGACY                  (XSTATE_MASK_LEGACY_FLOATING_POINT | XSTATE_MASK_LEGACY_SSE)
#define XSTATE_MASK_GSSE                    (1i64 << (XSTATE_GSSE))

#define MAXIMUM_XSTATE_FEATURES             64

	//
	// Extended processor state configuration
	//
#if defined(_WINNT_) && defined(_MSC_VER) && _MSC_VER < 1300
	typedef struct _XSTATE_FEATURE {
		DWORD Offset;
		DWORD Size;
	} XSTATE_FEATURE, * PXSTATE_FEATURE;

	typedef struct _XSTATE_CONFIGURATION {
		// Mask of enabled features
		DWORD64 EnabledFeatures;

		// Total size of the save area
		DWORD Size;

		DWORD OptimizedSave : 1;

		// List of features (
		XSTATE_FEATURE Features[MAXIMUM_XSTATE_FEATURES];

	} XSTATE_CONFIGURATION, * PXSTATE_CONFIGURATION;
#endif

#ifndef _WINDOWS_
	typedef enum _HEAP_INFORMATION_CLASS {
		HeapCompatibilityInformation
	} HEAP_INFORMATION_CLASS;
#endif //_WINDOWS_
#endif

	typedef enum _PS_ATTRIBUTE_NUM {
		PsAttributeParentProcess,
		PsAttributeDebugObject,
		PsAttributeToken,
		PsAttributeClientId,
		PsAttributeTebAddress,
		PsAttributeImageName,
		PsAttributeImageInfo,
		PsAttributeMemoryReserve,
		PsAttributePriorityClass,
		PsAttributeErrorMode,
		PsAttributeStdHandleInfo,
		PsAttributeHandleList,
		PsAttributeGroupAffinity,
		PsAttributePreferredNode,
		PsAttributeIdealProcessor,
		PsAttributeUmsThread,
		PsAttributeMitigationOptions,
		PsAttributeProtectionLevel,
		PsAttributeSecureProcess,
		PsAttributeJobList,
		PsAttributeChildProcessPolicy,
		PsAttributeAllApplicationPackagesPolicy,
		PsAttributeWin32kFilter,
		PsAttributeSafeOpenPromptOriginClaim,
		PsAttributeBnoIsolation,
		PsAttributeDesktopAppPolicy,
		PsAttributeChpe,
		PsAttributeMitigationAuditOptions,
		PsAttributeMachineType,
		PsAttributeComponentFilter,
		PsAttributeEnableOptionalXStateFeatures,
		PsAttributeMax
	} PS_ATTRIBUTE_NUM;

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED	0x01
#define PS_ATTRIBUTE_NUMBER_MASK				0x0000ffff
#define PS_ATTRIBUTE_THREAD						0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT						0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE					0x00040000 // Attribute may be <accumulated>, e.g. bitmasks, counters, etc.

#define PsAttributeValue(Number, Thread, Input, Additive)	\
    (((Number)	& PS_ATTRIBUTE_NUMBER_MASK) |				\
    ((Thread)	? PS_ATTRIBUTE_THREAD : 0) |				\
    ((Input)	? PS_ATTRIBUTE_INPUT : 0) |					\
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS						PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE) // 0x60000
#define PS_ATTRIBUTE_DEBUG_OBJECT						PsAttributeValue(PsAttributeDebugObject, FALSE, TRUE, TRUE) // 0x60001
#define PS_ATTRIBUTE_TOKEN								PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE) // 0x60002
#define PS_ATTRIBUTE_CLIENT_ID							PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE) // 0x10003
#define PS_ATTRIBUTE_TEB_ADDRESS						PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE) // 0x10004
#define PS_ATTRIBUTE_IMAGE_NAME							PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE) // 0x20005
#define PS_ATTRIBUTE_IMAGE_INFO							PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE) // 0x6
#define PS_ATTRIBUTE_MEMORY_RESERVE						PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE) // 0x20007
#define PS_ATTRIBUTE_PRIORITY_CLASS						PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE) // 0x20008
#define PS_ATTRIBUTE_ERROR_MODE							PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE) // 0x20009
#define PS_ATTRIBUTE_STD_HANDLE_INFO					PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE) // 0x2000A
#define PS_ATTRIBUTE_HANDLE_LIST						PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE) // 0x2000B
#define PS_ATTRIBUTE_GROUP_AFFINITY						PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE) // 0x2000C
#define PS_ATTRIBUTE_PREFERRED_NODE						PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE) // 0x2000D
#define PS_ATTRIBUTE_IDEAL_PROCESSOR					PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE) // 0x2000E
#define PS_ATTRIBUTE_MITIGATION_OPTIONS					PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE) // 0x60010
#define PS_ATTRIBUTE_PROTECTION_LEVEL					PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE) // 0x20011
#define PS_ATTRIBUTE_SECURE_PROCESS						PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE) // 0x20012
#define PS_ATTRIBUTE_JOB_LIST							PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE) // 0x20013
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY				PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE) // 0x20014
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY	PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE) // 0x20015
#define PS_ATTRIBUTE_WIN32K_FILTER						PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE) // 0x20016
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM		PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE) // 0x20017
#define PS_ATTRIBUTE_BNO_ISOLATION						PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE) // 0x20018
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY					PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE) // 0x20019
#define PS_ATTRIBUTE_CHPE								PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE) // 0x6001A
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS			PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE) // 0x2001B
#define PS_ATTRIBUTE_MACHINE_TYPE						PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE) // 0x6001C
#define PS_ATTRIBUTE_COMPONENT_FILTER					PsAttributeValue(PsAttributeComponentFilter, FALSE, TRUE, FALSE) // 0x2001D
#define PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES	PsAttributeValue(PsAttributeEnableOptionalXStateFeatures, TRUE, TRUE, FALSE) // 0x3001E

	typedef struct _CLIENT_ID {
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID, * PCLIENT_ID;


	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING;
	typedef UNICODE_STRING* PUNICODE_STRING;


	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


	typedef struct _PS_ATTRIBUTE {
		ULONG_PTR Attribute;                // PROC_THREAD_ATTRIBUTE_XXX | PROC_THREAD_ATTRIBUTE_XXX modifiers, see ProcThreadAttributeValue macro and Windows Internals 6 (372)
		SIZE_T Size;                        // Size of Value or *ValuePtr
		union {

			ULONG_PTR Value;                // Reserve 8 bytes for data (such as a Handle or a data pointer)
			PVOID ValuePtr;                 // data pointer
		};
		PSIZE_T ReturnLength;               // Either 0 or specifies size of data returned to caller via <ValuePtr>
	} PS_ATTRIBUTE, * PPS_ATTRIBUTE;


	typedef enum _PS_IFEO_KEY_STATE {
		PsReadIFEOAllValues,
		PsSkipIFEODebugger,
		PsSkipAllIFEO,
		PsMaxIFEOKeyStates

	} PS_IFEO_KEY_STATE, * PPS_IFEO_KEY_STATE;


	typedef enum _PS_CREATE_STATE {
		PsCreateInitialState,
		PsCreateFailOnFileOpen,
		PsCreateFailOnSectionCreate,
		PsCreateFailExeFormat,
		PsCreateFailMachineMismatch,
		PsCreateFailExeName, // Debugger specified
		PsCreateSuccess,
		PsCreateMaximumStates
	} PS_CREATE_STATE;


	typedef struct _PS_CREATE_INFO {
		SIZE_T Size;
		PS_CREATE_STATE State;
		union {
			// PsCreateInitialState
			struct {
				union {

					ULONG InitFlags;
					struct {

						UCHAR WriteOutputOnExit : 1;
						UCHAR DetectManifest : 1;
						UCHAR IFEOSkipDebugger : 1;
						UCHAR IFEODoNotPropagateKeyState : 1;
						UCHAR SpareBits1 : 4;
						UCHAR SpareBits2 : 8;
						USHORT ProhibitedImageCharacteristics : 16;
					} s1;
				} u1;
				ACCESS_MASK AdditionalFileAccess;
			} InitState;

			struct {
				HANDLE FileHandle;
			} FailSection;

			struct {
				USHORT DllCharacteristics;
			} ExeFormat;

			struct {
				HANDLE IFEOKey;
			} ExeName;

			struct {
				union {
					ULONG OutputFlags;
					struct {

						UCHAR ProtectedProcess : 1;
						UCHAR AddressSpaceOverride : 1;
						UCHAR DevOverrideEnabled : 1; // From Image File Execution Options
						UCHAR ManifestDetected : 1;
						UCHAR ProtectedProcessLight : 1;
						UCHAR SpareBits1 : 3;
						UCHAR SpareBits2 : 8;
						USHORT SpareBits3 : 16;
					} s2;
				} u2;
				HANDLE FileHandle;
				HANDLE SectionHandle;
				ULONGLONG UserProcessParametersNative;
				ULONG UserProcessParametersWow64;
				ULONG CurrentParameterFlags;
				ULONGLONG PebAddressNative;
				ULONG PebAddressWow64;
				ULONGLONG ManifestAddress;
				ULONG ManifestSize;
			} SuccessState;
		};
	} PS_CREATE_INFO, * PPS_CREATE_INFO;


	typedef struct _PS_ATTRIBUTE_LIST {
		SIZE_T TotalLength;                 // sizeof(PS_ATTRIBUTE_LIST)
		PS_ATTRIBUTE Attributes[1];         // Depends on how many attribute entries should be supplied to NtCreateUserProcess
	} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


	typedef struct _CURDIR {
		UNICODE_STRING DosPath;
		HANDLE Handle;
	} CURDIR, * PCURDIR;


	typedef struct _RTL_DRIVE_LETTER_CURDIR {
		USHORT Flags;
		USHORT Length;
		ULONG TimeStamp;
		UNICODE_STRING DosPath;

	} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


	typedef struct _KSYSTEM_TIME {
		ULONG LowPart;
		LONG High1Time;
		LONG High2Time;
	} KSYSTEM_TIME, * PKSYSTEM_TIME;


	typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
		StandardDesign,
		NEC98x86,
		EndAlternatives
	} ALTERNATIVE_ARCHITECTURE_TYPE;


	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER SpareLi1;
		LARGE_INTEGER SpareLi2;
		LARGE_INTEGER SpareLi3;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR PageDirectoryBase;
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
	} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


typedef struct __attribute__((packed)) {
	ULONG ExtendedProcessInfo;
	ULONG ExtendedProcessInfoBuffer;
} EXTENDED_PROCESS_INFORMATION, *PEXTENDED_PROCESS_INFORMATION;

#define RTL_MAX_DRIVE_LETTERS 32
	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		ULONG MaximumLength;
		ULONG Length;

		ULONG Flags;
		ULONG DebugFlags;

		HANDLE ConsoleHandle;
		ULONG ConsoleFlags;
		HANDLE StandardInput;
		HANDLE StandardOutput;
		HANDLE StandardError;

		CURDIR CurrentDirectory;
		UNICODE_STRING DllPath;
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
		PWCHAR Environment;

		ULONG StartingX;
		ULONG StartingY;
		ULONG CountX;
		ULONG CountY;
		ULONG CountCharsX;
		ULONG CountCharsY;
		ULONG FillAttribute;

		ULONG WindowFlags;
		ULONG ShowWindowFlags;
		UNICODE_STRING WindowTitle;
		UNICODE_STRING DesktopInfo;
		UNICODE_STRING ShellInfo;
		UNICODE_STRING RuntimeData;
		RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

		ULONG_PTR EnvironmentSize;
		ULONG_PTR EnvironmentVersion;
		PVOID PackageDependencyData;
		ULONG ProcessGroupId;
		ULONG LoaderThreads;

	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


	typedef struct _KUSER_SHARED_DATA {
		ULONG TickCountLowDeprecated;
		ULONG TickCountMultiplier;

		volatile KSYSTEM_TIME InterruptTime;
		volatile KSYSTEM_TIME SystemTime;
		volatile KSYSTEM_TIME TimeZoneBias;

		USHORT ImageNumberLow;
		USHORT ImageNumberHigh;
		WCHAR NtSystemRoot[260];
		ULONG MaxStackTraceDepth;
		ULONG CryptoExponent;
		ULONG TimeZoneId;
		ULONG LargePageMinimum;
		ULONG Reserved2[7];
		ULONG NtProductType;
		BOOLEAN ProductTypeIsValid;
		ULONG NtMajorVersion;
		ULONG NtMinorVersion;
		BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
		ULONG Reserved1;
		ULONG Reserved3;

		volatile ULONG TimeSlip;

		ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
		LARGE_INTEGER SystemExpirationDate;
		ULONG SuiteMask;
		BOOLEAN KdDebuggerEnabled;
		UCHAR NXSupportPolicy;

		volatile ULONG ActiveConsoleId;
		volatile ULONG DismountCount;

		ULONG ComPlusPackage;
		ULONG LastSystemRITEventTickCount;
		ULONG NumberOfPhysicalPages;
		BOOLEAN SafeBootMode;
		union {
			UCHAR TscQpcData;
			struct {
				UCHAR TscQpcEnabled : 1;
				UCHAR TscQpcSpareFlag : 1;
				UCHAR TscQpcShift : 6;
			};
		};
		UCHAR TscQpcPad[2];

		union {
			ULONG TraceLogging;
			ULONG SharedDataFlags;
			struct {
				ULONG DbgErrorPortPresent : 1;
				ULONG DbgElevationEnabled : 1;
				ULONG DbgVirtEnabled : 1;
				ULONG DbgInstallerDetectEnabled : 1;
				ULONG DbgSystemDllRelocated : 1;
				ULONG DbgDynProcessorEnabled : 1;
				ULONG DbgSEHValidationEnabled : 1;
				ULONG SpareBits : 25;
			};
		};
		ULONG DataFlagsPad[1];

		ULONGLONG TestRetInstruction;
		ULONG SystemCall;
		ULONG SystemCallReturn;
		ULONGLONG SystemCallPad[3];

		union
		{
			volatile KSYSTEM_TIME TickCount;
			volatile ULONG64 TickCountQuad;
			struct
			{
				ULONG ReservedTickCountOverlay[3];
				ULONG TickCountPad[1];
			};
		};

		ULONG Cookie;

		// Entries below all invalid below Windows Vista

		ULONG CookiePad[1];
		LONGLONG ConsoleSessionForegroundProcessId;
		ULONG Wow64SharedInformation[MAX_WOW64_SHARED_ENTRIES];
		USHORT UserModeGlobalLogger[16];
		ULONG ImageFileExecutionOptions;
		ULONG LangGenerationCount;

		union {
			ULONGLONG AffinityPad; // only valid on Windows Vista
			ULONG_PTR ActiveProcessorAffinity; // only valid on Windows Vista
			ULONGLONG Reserved5;
		};
		volatile ULONG64 InterruptTimeBias;
		volatile ULONG64 TscQpcBias;

		volatile ULONG ActiveProcessorCount;
		volatile USHORT ActiveGroupCount;
		USHORT Reserved4;

		volatile ULONG AitSamplingValue;
		volatile ULONG AppCompatFlag;

		ULONGLONG SystemDllNativeRelocation;
		ULONG SystemDllWowRelocation;

		ULONG XStatePad[1];
		XSTATE_CONFIGURATION XState;
	} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;


	typedef enum _PROCESSINFOCLASS {
		ProcessBasicInformation = 0,
		ProcessDebugPort = 7,
		ProcessUserModeIOPL = 16,
		ProcessWow64Information = 26,
		ProcessImageFileName = 27,
		ProcessBreakOnTermination = 29,
		ProcessCookie = 36
	} PROCESSINFOCLASS;


	typedef struct _BASE_RELOCATION_BLOCK {
		DWORD   VirtualAddress;
		DWORD   SizeOfBlock;
	} 	BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;


	typedef struct _BASE_RELOCATION_ENTRY {
		USHORT Offset : 12;
		USHORT Type : 4;
	} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

/*
	typedef struct _LDR_MODULE {
		LIST_ENTRY      InLoadOrderModuleList;
		LIST_ENTRY      InMemoryOrderModuleList;
		LIST_ENTRY      InInitializationOrderModuleList;
		PVOID           BaseAddress;
		PVOID           EntryPoint;
		ULONG           SizeOfImage;
		UNICODE_STRING  FullDllName;
		UNICODE_STRING  BaseDllName;
		ULONG           Flags;
		SHORT           LoadCount;
		SHORT           TlsIndex;
		LIST_ENTRY      HashTableEntry;
		ULONG           TimeDateStamp;
	} LDR_MODULE, * PLDR_MODULE;
*/


	typedef struct _PEB_LDR_DATA {
		BYTE Reserved1[8];
		PVOID Reserved2[3];
		LIST_ENTRY InMemoryOrderModuleList;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;


	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		union {
			LIST_ENTRY HashLinks;
			struct {
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union {
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		} t;
		PVOID EntryPointActivationContext;
		PVOID PatchInformation;
		LIST_ENTRY ForwarderLinks;
		LIST_ENTRY ServiceTagLinks;
		LIST_ENTRY StaticLinks;
		PVOID ContextInformation;
		ULONG_PTR OriginalBase;
		LARGE_INTEGER LoadTime;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


	typedef const struct _LDR_DATA_TABLE_ENTRY* PCLDR_DATA_TABLE_ENTRY;


	typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);


	typedef struct _PEB_FREE_BLOCK {
		_PEB_FREE_BLOCK* Next;
		ULONG            Size;
	} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;


	typedef void (*PPEBLOCKROUTINE)(PVOID PebLock);


	typedef struct _API_SET_NAMESPACE {
		ULONG Version;
		ULONG Size;
		ULONG Flags;
		ULONG Count;
		ULONG EntryOffset;
		ULONG HashOffset;
		ULONG HashFactor;

	} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;


#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

	typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
	typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
	typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];

	typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
		ULONG Flags;
		PSTR FrameName;
	} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;


	typedef struct _TEB_ACTIVE_FRAME {
		ULONG Flags;
		struct _TEB_ACTIVE_FRAME* Previous;
		PTEB_ACTIVE_FRAME_CONTEXT Context;
	} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;


	typedef struct _PEB {
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
		PRTL_USER_PROCESS_PARAMETERS ProcessParams;
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
				ULONG ProcessImagesHotPatched : 1; // REDSTONE5
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
		PVOID TlsBitmap;
		ULONG TlsBitmapBits[2];

		PVOID ReadOnlySharedMemoryBase;
		PVOID SharedData; // HotpatchInformation
		PVOID ReadOnlyStaticServerData;

		PVOID AnsiCodePageData; // PCPTABLEINFO
		PVOID OemCodePageData; // PCPTABLEINFO
		PVOID UnicodeCaseTableData; // PNLSTABLEINFO

		ULONG NumberOfProcessors;
		ULONG NtGlobalFlag;

		ULARGE_INTEGER CriticalSectionTimeout;
		SIZE_T HeapSegmentReserve;
		SIZE_T HeapSegmentCommit;
		SIZE_T HeapDeCommitTotalFreeThreshold;
		SIZE_T HeapDeCommitFreeBlockThreshold;

		ULONG NumberOfHeaps;
		ULONG MaximumNumberOfHeaps;
		PVOID ProcessHeaps; // PHEAP

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

		PVOID TlsExpansionBitmap;
		ULONG TlsExpansionBitmapBits[32];

		ULONG SessionId;

		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		PVOID pShimData;
		PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

		UNICODE_STRING CSDVersion;

		PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
		PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
		PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
		PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

		SIZE_T MinimumStackCommit;

		PVOID SparePointers[2]; // 19H1 (previously FlsCallback to FlsHighIndex)
		PVOID PatchLoaderData;
		PVOID ChpeV2ProcessInfo; // _CHPEV2_PROCESS_INFO

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
			PVOID pContextData; // WIN7
			PVOID pUnused; // WIN10
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
		PVOID TelemetryCoverageHeader; // REDSTONE3
		ULONG CloudFileFlags;
		ULONG CloudFileDiagFlags; // REDSTONE4
		CHAR PlaceholderCompatibilityMode;
		CHAR PlaceholderCompatibilityModeReserved[7];
		struct _LEAP_SECOND_DATA* LeapSecondData; // REDSTONE5
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


	typedef struct _TEB {
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
		PVOID SystemReserved1[54];
		NTSTATUS ExceptionCode;
		PVOID ActivationContextStackPointer;
#if defined(_M_X64)
		UCHAR SpareBytes[24];
#else
		UCHAR SpareBytes[36];
#endif
		ULONG TxFsContext;

		//GDI_TEB_BATCH GdiTebBatch;
		CLIENT_ID RealClientId;
		HANDLE GdiCachedProcessHandle;
		ULONG GdiClientPID;
		ULONG GdiClientTID;
		PVOID GdiThreadLocalInfo;
		ULONG_PTR Win32ClientInfo[62];
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
		WCHAR StaticUnicodeBuffer[261];

		PVOID DeallocationStack;
		PVOID TlsSlots[64];
		LIST_ENTRY TlsLinks;

		PVOID Vdm;
		PVOID ReservedForNtRpc;
		PVOID DbgSsReserved[2];

		ULONG HardErrorMode;
#if defined(_M_X64)
		PVOID Instrumentation[11];
#else
		PVOID Instrumentation[9];
#endif
		GUID ActivityId;

		PVOID SubProcessTag;
		PVOID EtwLocalData;
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
		PVOID ReservedForOle;
		ULONG WaitingOnLoaderLock;
		PVOID SavedPriorityState;
		ULONG_PTR SoftPatchPtr1;
		PVOID ThreadPoolData;
		PVOID* TlsExpansionSlots;
#if defined(_M_X64)
		PVOID DeallocationBStore;
		PVOID BStoreLimit;
#endif
		ULONG MuiGeneration;
		ULONG IsImpersonating;
		PVOID NlsCache;
		PVOID pShimData;
		ULONG HeapVirtualAffinity;
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
				USHORT SpareSameTebBits : 1;
			};
		};

		PVOID TxnScopeEnterCallback;
		PVOID TxnScopeExitCallback;
		PVOID TxnScopeContext;
		ULONG LockCount;
		ULONG SpareUlong0;
		PVOID ResourceRetValue;
	} TEB, * PTEB;


	/*
#ifdef _WIN64
	C_ASSERT(FIELD_OFFSET(PEB, SessionId) == 0x2C0);
	C_ASSERT(sizeof(PEB) == 0x7d0); // WIN11
#else
	C_ASSERT(FIELD_OFFSET(PEB, SessionId) == 0x1D4);
	C_ASSERT(sizeof(PEB) == 0x488); // WIN11
#endif
	*/


#define GDI_BATCH_BUFFER_SIZE 0x136
	typedef struct _GDI_TEB_BATCH {
		ULONG Offset;
		HANDLE HDC;
		ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
	} GDI_TEB_BATCH, * PGDI_TEB_BATCH;


	typedef struct _PROCESS_BASIC_INFORMATION {
		PVOID Reserved1;
		PEB* PebBaseAddress;
		PVOID Reserved2[2];
		ULONG_PTR UniqueProcessId;
		PVOID Reserved3;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;


	typedef struct _LOADED_IMAGE {
		PSTR                        ModuleName;
		HANDLE                      hFile;
		PUCHAR                      MappedAddress;
#ifdef _M_IX86
		PIMAGE_NT_HEADERS32         FileHeader;
#else
		PIMAGE_NT_HEADERS64         FileHeader;
#endif
		PIMAGE_SECTION_HEADER       LastRvaSection;
		WORD						NumberOfSections;
		PIMAGE_SECTION_HEADER       Sections;
		ULONG                       Characteristics;
		BOOLEAN                     fSystemImage;
		BOOLEAN                     fDOSImage;
		BOOLEAN                     fReadOnly;
		UCHAR                       Version;
		LIST_ENTRY                  Links;
		ULONG                       SizeOfImage;
	} LOADED_IMAGE, * PLOADED_IMAGE;


	typedef enum _SECTION_INHERIT {
		viewShare = 1,
		viewUnmap = 2
	} SECTION_INHERIT;


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
		SystemVdmInstemulInformation,
		SystemVdmBopInformation,
		SystemFileCacheInformation,
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
		/*
		#if !defined PO_CB_SYSTEM_POWER_POLICY
			SystemPowerInformation,
		#else
			_SystemPowerInformation,
		#endif
		*/
		SystemProcessorSpeedInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation

	} SYSTEM_INFORMATION_CLASS;


	typedef LONG(*PRTL_HEAP_COMMIT_ROUTINE)(PVOID Base, PVOID* CommitAddress, ULONG_PTR CommitSize);


	typedef struct _RTL_HEAP_PARAMETERS {

		ULONG Length;
		ULONG SegmentReserve;
		ULONG SegmentCommit;
		ULONG DeCommitFreeBlockThreshold;
		ULONG DeCommitTotalFreeThreshold;
		ULONG MaximumAllocationSize;
		ULONG VirtualMemoryThreshold;
		ULONG InitialCommit;
		ULONG InitialReserve;
		PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
		ULONG Reserved[2];

	} RTL_HEAP_PARAMETERS, * PRTL_HEAP_PARAMETERS;


	typedef ULONG_PTR ERESOURCE_THREAD, * PERESOURCE_THREAD;


#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5


	typedef enum _MEMORY_INFORMATION_CLASS {

		MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
		MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
		MemoryMappedFilenameInformation, // UNICODE_STRING
		MemoryRegionInformation, // MEMORY_REGION_INFORMATION
		MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
		MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
		MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
		MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
		MemoryPrivilegedBasicInformation,
		MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
		MemoryBasicInformationCapped, // 10
		MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
		MemoryBadInformation, // since WIN11
		MemoryBadInformationAllProcesses, // since 22H1
		MaxMemoryInfoClass

	} MEMORY_INFORMATION_CLASS;


	typedef struct _MEMORY_IMAGE_INFORMATION {

		PVOID ImageBase;
		SIZE_T SizeOfImage;
		union
		{
			ULONG ImageFlags;
			struct
			{
				ULONG ImagePartialMap : 1;
				ULONG ImageNotExecutable : 1;
				ULONG ImageSigningLevel : 4; // REDSTONE3
				ULONG Reserved : 26;
			};
		};
 } MEMORY_IMAGE_INFORMATION, * PMEMORY_IMAGE_INFORMATION;

typedef enum _THREADINFOCLASS {
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


C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountMultiplier) == 0x4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTime) == 0x8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemTime) == 0x14);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneBias) == 0x20);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageNumberLow) == 0x2c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageNumberHigh) == 0x2e);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtSystemRoot) == 0x30);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, MaxStackTraceDepth) == 0x238);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, CryptoExponent) == 0x23c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneId) == 0x240);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LargePageMinimum) == 0x244);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved2) == 0x248);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtProductType) == 0x264);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ProductTypeIsValid) == 0x268);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMajorVersion) == 0x26c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMinorVersion) == 0x270);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ProcessorFeatures) == 0x274);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved1) == 0x2b4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved3) == 0x2b8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeSlip) == 0x2bc);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AlternativeArchitecture) == 0x2c0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemExpirationDate) == 0x2c8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SuiteMask) == 0x2d0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, KdDebuggerEnabled) == 0x2d4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NXSupportPolicy) == 0x2d5);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveConsoleId) == 0x2d8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, DismountCount) == 0x2dC);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ComPlusPackage) == 0x2e0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LastSystemRITEventTickCount) == 0x2e4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NumberOfPhysicalPages) == 0x2e8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SafeBootMode) == 0x2ec);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TraceLogging) == 0x2f0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TestRetInstruction) == 0x2f8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCall) == 0x300);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCallReturn) == 0x304);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCallPad) == 0x308);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCount) == 0x320);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountQuad) == 0x320);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Cookie) == 0x330);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ConsoleSessionForegroundProcessId) == 0x338);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Wow64SharedInformation) == 0x340);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, UserModeGlobalLogger) == 0x380);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageFileExecutionOptions) == 0x3a0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LangGenerationCount) == 0x3a4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTimeBias) == 0x3b0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, UserModeGlobalLogger) == 0x380);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageFileExecutionOptions) == 0x3a0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LangGenerationCount) == 0x3a4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved5) == 0x3a8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTimeBias) == 0x3b0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TscQpcBias) == 0x3b8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveProcessorCount) == 0x3c0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveGroupCount) == 0x3c4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved4) == 0x3c6);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AitSamplingValue) == 0x3c8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AppCompatFlag) == 0x3cc);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemDllNativeRelocation) == 0x3d0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemDllWowRelocation) == 0x3d8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, XState) == 0x3e0);

#define SHARED_USER_DATA_VA 0x7FFE0000
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)SHARED_USER_DATA_VA)

__inline struct _KUSER_SHARED_DATA* GetKUserSharedData() {
	return (USER_SHARED_DATA);
}

__forceinline ULONG NtGetTickCount() {
	return (ULONG) ((USER_SHARED_DATA->TickCountQuad * USER_SHARED_DATA->TickCountMultiplier) >> 24);
}
#endif
