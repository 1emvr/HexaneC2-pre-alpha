#ifndef HEXANE_MONOLITH_HPP
#define HEXANE_MONOLITH_HPP
#include <core/ntimports.hpp>

EXTERN_C ULONG __global;
EXTERN_C LPVOID InstStart();
EXTERN_C LPVOID InstEnd();

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

#define WIN_VERSION_UNKNOWN     		0
#define WIN_VERSION_XP          		1
#define WIN_VERSION_VISTA       		2
#define WIN_VERSION_2008        		3
#define WIN_VERSION_7           		4
#define WIN_VERSION_2008_R2     		5
#define WIN_VERSION_2012        		7
#define WIN_VERSION_8           		8
#define WIN_VERSION_8_1         		8.1
#define WIN_VERSION_2012_R2     		9
#define WIN_VERSION_10          		10
#define WIN_VERSION_2016_X      		11


#define Ntstatus                        Ctx->Teb->LastErrorValue
#define RVA(T, b, r)                    (T) ((UINT_PTR)(b) + (UINT_PTR)(r))

#define DTYPE(x)						decltype(x) *x
#define DATA_SECTION(x)                 __attribute__((used, section(".data")))
#define TEXT_SECTION(x)                 __attribute__((used, section(".text")))
#define DLL_EXPORT                      __declspec(dllexport)

#define PS_ATTR_LIST_SIZE(n)            (sizeof(PS_ATTRIBUTE_LIST) + (sizeof(PS_ATTRIBUTE) * (n - 1)))
#define MODULE_NAME(mod)				(mod->BaseDllName.Buffer)

#define PEB_POINTER64                   ((PPEB) __readgsqword(0x60))
#define PEB_POINTER32                   ((PPEB) __readfsdword(0x30))
#define REG_PEB32(thr)                  ((LPVOID) (ULONG_PTR) thr.Ebx + 0x8)
#define REG_PEB64(thr)                  ((LPVOID) (ULONG_PTR) thr.Rdx + 0x10)

#define ITER_SECTION_HEADER(data, i)	((PIMAGE_SECTION_HEADER) (PBYTE)(data) + sizeof(IMAGE_FILE_HEADER) + (sizeof(IMAGE_SECTION_HEADER) * i))
#define SYMBOL_TABLE(data, nt_head) 	RVA(COFF_SYMBOL*, data, nt_head->FileHeader.PointerToSymbolTable)
#define RELOC_SECTION(data, section)	RVA(RELOC*, data, section->PointerToRelocations)
#define SEC_START(map, index)           (UINT_PTR)((PBYTE)(map[index].address))
#define SEC_END(map, index)             (UINT_PTR)((PBYTE)(map[index].address) + map[index].size)

#define NtCurrentProcess()              ((HANDLE) (LONG_PTR) -1)
#define NtCurrentThread()               ((HANDLE) (LONG_PTR) -2)
#define PIPE_BUFFER_MAX                 (64 * 1000 - 1)
#define NT_SUCCESS(x)                   (x >= 0)

#define NONCE_SIZE                      ((UINT32) 16)
#define DH_KEY_SIZE                     ((UINT32) 2048)
#define AES_KEY_SIZE					((UINT32) 16)

#define INIT_LIST_ENTRY(entry)          ((entry)->Blink = (entry)->Flink = (entry))
#define F_PTR_HMOD(F, M, SH)            (F = (decltype(F)) Modules::FindExportAddress(M, SH))
#define F_PTR_HASHES(F, MH, SH)         (F = (decltype(F)) Modules::FindExportAddress((Modules::FindModuleEntry(MH)->DllBase), SH))
#define C_PTR_HASHES(F, MH, SH)         (F = (void*) Modules::FindExportAddress((Modules::FindModuleEntry(MH)->DllBase), SH))
#define M_PTR(MH)                       ((Modules::FindModuleEntry(MH))->DllBase)

#if	defined(__GNUC__) || defined(__GNUG__)
#define __bswap32 __bswapd
#define __bswap64 __bswapq
#endif

#define RANDOM(n)               (Utils::Random::RandomNumber32() % (n))
#define PAGE_ALIGN(x)           ((PBYTE)(U_PTR(x) + ((4096 - (U_PTR(x) & (4096 - 1))) % 4096)))
#define ARRAY_LEN(p)            sizeof(p) / sizeof(p[0])
#define DYN_ARRAY_LEN(i, p)     while (p[i]) { i++; }
#define IN_RANGE(b, e, x)       (x >= b && x < e)

#define FILL_MBS(s, b)							\
	s.Length = (USHORT) MbsLength(b);			\
	s.Capacity = s.Length;						\
	s.Buffer = b

#define FILL_WCS(s, b)							\
	s.Length = (USHORT) WcsLength(b);			\
	s.Capacity = s.Length;						\
	s.Buffer = b

#define InitializeObjectAttributes(ptr, name, attr, root, sec)	\
	(ptr)->Length = sizeof( OBJECT_ATTRIBUTES);					\
	(ptr)->RootDirectory = root;								\
	(ptr)->Attributes = attr;									\
	(ptr)->ObjectName = name;									\
	(ptr)->SecurityDescriptor = sec;							\
	(ptr)->SecurityQualityOfService = NULL

#ifdef _M_X64
#define X64                                     true
#define IP_REG                                  Rip
#define ENTRYPOINT_REG                          Rcx
#define PTR_MASK                                0x7FFFFFFF
#define PEB_POINTER                             PEB_POINTER64
#define REG_PEB_OFFSET(x)                       REG_PEB64(x)
#define DBG_FLAG_OFFSET                         DBG_FLAG_OFFSET64
#define IMAGE_OPT_MAGIC                         IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define MACHINE_ARCH                            IMAGE_FILE_MACHINE_AMD64

#define COFF_PREP_SYMBOL                        0xec6ba2a8  // __imp_
#define COFF_PREP_SYMBOL_SIZE                   6
#define COFF_PREP_BEACON                        0xd0a409b0  // __imp_Beacon
#define COFF_PREP_BEACON_SIZE                   (COFF_PREP_SYMBOL_SIZE + 6)
#define COFF_INSTANCE                           0xbfded9c9  // .refptr.__instance // TODO: update this name hash
#elif _M_IX86
#define X64                                     false
#define IP_REG                                  Eip
#define ENTRYPOINT_REG                          Eax
#define PTR_MASK                                0x7FFF
#define PEB_POINTER                             PEB_POINTER32
#define REG_PEB_OFFSET(x)                       REB_PEB32(x)
#define DBG_FLAG_OFFSET                         DBG_FLAG_OFFSET32
#define IMAGE_OPT_MAGIC                         IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define MACHINE_ARCH                            IMAGE_FILE_MACHINE_I386

#define COFF_PREP_SYMBOL                        0x79dff807  // __imp__
#define COFF_PREP_SYMBOL_SIZE                   7
#define COFF_PREP_BEACON                        0x4c20aa4f  // __imp__Beacon
#define COFF_PREP_BEACON_SIZE                   (COFF_PREP_SYMBOL_SIZE + 6)
#define COFF_INSTANCE                           0xb341b5b9  // __instance // TODO: update this name hash
#endif

#ifdef TRANSPORT_HTTP
#define TRANSPORT_TYPE 1
#elifdef TRANSPORT_PIPE
#define TRANSPORT_TYPE 0
#endif
#define ROOT_NODE TRANSPORT_TYPE

#define EGRESS                                      0
#define INGRESS                                     1
#define HEAP_NO_COMMIT                              0,0,0,0,0
#define DESKTOP_ENVIRONMENT_NULL                    0,0,0,0,0,0,0
#define PROCESS_CREATE_ALL_ACCESS_SUSPEND           PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, nullptr, nullptr, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define IMAGE_SCN_MEM_RWX                           (IMAGE_SCN_MEM_EXECUTE |IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
#define IMAGE_SCN_MEM_RW                            (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
#define IMAGE_SCN_MEM_RX                            (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE)
#define IMAGE_SCN_MEM_WX                            (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)

#define UNMANAGED_PROCESS                           0
#define MANAGED_PROCESS                             1
#define ERROR_EXIT                                  0x7FFFFFFF
#define DBG_FLAG_OFFSET64                           0x000000BC
#define DBG_FLAG_OFFSET32                           0x00000068
#define FLG_HEAP_ENABLE_TAIL_CHECK                  0x00000020
#define FLG_HEAP_ENABLE_FREE_CHECK                  0x00000040
#define FLG_HEAP_VALIDATE_PARAMETERS                0x40000000
#define ADDRESS_MAX                                 0xFFFFFFFFFFF70000
#define VM_MAX                                      0x70000000
#define IOCTL1                                      0x80862007

#pragma region TLV
#define HEADER_SIZE                                 (sizeof(UINT32) * 3)
#define SEGMENT_HEADER_SIZE                         ((sizeof(UINT32) * 6) + sizeof(UINT32))
#define HTTP_REQUEST_MAX                            0x300000
#pragma endregion

#define THREAD_CREATE_FLAGS_NONE                    0x00000000
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED        0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH      0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER      0x00000004
#define THREAD_CREATE_FLAGS_LOADER_WORKER           0x00000010
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT        0x00000020
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE   0x00000040

#define DEFAULT_SECTION_SIZE                        0x1000
#define DEFAULT_BUFFLEN                             0x0400

#ifdef TRANSPORT_PIPE
#define MESSAGE_MAX PIPE_BUFFER_MAX
#else
#define MESSAGE_MAX HTTP_REQUEST_MAX
#endif

typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE processHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE processHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_t)(HANDLE processHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(HANDLE processHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(HANDLE SectionHandle, HANDLE processHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t) (HANDLE processHandle, PVOID BaseAddress);
typedef HRESULT(NTAPI* CLRCreateInstance_t)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);

typedef PVOID(NTAPI* RtlCreateHeap_t)(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PRTL_HEAP_PARAMETERS Parameters);
typedef PVOID(NTAPI* RtlAllocateHeap_t)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
typedef PVOID(NTAPI* RtlReAllocateHeap_t)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);
typedef PVOID(NTAPI* RtlDestroyHeap_t)(PVOID HeapHandle);
typedef LOGICAL(NTAPI* RtlFreeHeap_t)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE hProcess, ACCESS_MASK dwDesiredAccess, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(NTAPI* NtOpenProcessToken_t)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
typedef NTSTATUS(NTAPI* NtOpenThreadToken_t)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle);
typedef NTSTATUS(NTAPI* NtDuplicateToken_t)(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE Type, PHANDLE NewTokenHandle);
typedef NTSTATUS(NTAPI* NtDuplicateObject_t)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
typedef NTSTATUS(NTAPI* NtOpenThread_t)( PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PUSER_THREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS(NTAPI* NtTerminateThread_t)(HANDLE ThreadHandle, NTSTATUS ExitStatus);

typedef NTSTATUS (NTAPI* NtDeviceIoControlFile_t)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
typedef NTSTATUS (NTAPI* NtOpenFile_t)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
typedef NTSTATUS(NTAPI* NtQueryInformationToken_t)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* NtCreateUserProcess_t)(PHANDLE processHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParams, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST ProcessAttributeList);
typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
typedef NTSTATUS(NTAPI* RtlCreateProcessParametersEx_t)(PRTL_USER_PROCESS_PARAMETERS* params, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* RtlDestroyProcessParameters_t)(PRTL_USER_PROCESS_PARAMETERS procParams);
typedef NTSTATUS (NTAPI* RtlHashUnicodeString_t)(PCUNICODE_STRING String, BOOLEAN CaseInSensitive, ULONG HashAlgorithm, PULONG HashValue);
typedef BOOLEAN (NTAPI* RtlRbInsertNodeEx_t)(PRTL_RB_TREE Tree, PRTL_BALANCED_NODE Parent, BOOLEAN Right, PRTL_BALANCED_NODE Node);
typedef NTSTATUS (NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW lpVersionInformation);
typedef NTSTATUS (NTAPI* NtQuerySystemTime_t)(PLARGE_INTEGER SystemTime);
typedef ULONG (NTAPI* RtlRandomEx_t)(PULONG Seed);

typedef BOOL (WINAPI* SetProcessValidCallTargets_t)(HANDLE hProcess, PVOID VirtualAddress, SIZE_T RegionSize, ULONG NumberOfOffsets, PCFG_CALL_TARGET_INFO OffsetInformation);
typedef PVOID (NTAPI* RtlAddVectoredExceptionHandler_t)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef ULONG (NTAPI* RtlRemoveVectoredExceptionHandler_t)(PVOID Handle);
typedef NTSTATUS(NTAPI* NtGetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(NTAPI* NtSetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(NTAPI* NtResumeThread_t)(HANDLE hThr, PULONG PrviousSuspendCount);
typedef NTSTATUS(NTAPI* NtWaitForSingleObject_t)(HANDLE Handle, BOOLEAN Alertable, ULONG Timeout);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE hObject);
typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING Destinationstring, PCWSTR Sourcestring);
typedef NTSTATUS (NTAPI* NtTestAlert_t)(void);
typedef NTSTATUS (NTAPI* TpAllocWork_t)(PTP_WORK* ptpWork, PTP_WORK_CALLBACK callback, PVOID optArgs, PTP_CALLBACK_ENVIRON cbEnviron);
typedef VOID (NTAPI* TpPostWork_t)(PTP_WORK ptpWork);
typedef VOID (NTAPI* TpReleaseWork_t)(PTP_WORK ptpWork);

typedef NTSTATUS (NTAPI* NtDelayExecution_t)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
typedef NTSTATUS (NTAPI* NtCreateEvent_t)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
typedef NTSTATUS (NTAPI* NtQueueApcThread_t)(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
typedef NTSTATUS (NTAPI* NtContinue_t)(PCONTEXT ContextRecord, BOOLEAN TestAlert);
typedef NTSTATUS (NTAPI* NtAlertResumeThread_t)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS (NTAPI* NtSignalAndWaitForSingleObject_t)(HANDLE SignalHandle, HANDLE WaitHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

enum ModuleType {
    LocalFile, RemoteFile, Memory, LoadBof, NoLink,
};

enum MessageType {
    CheckIn, Tasking, Response, Segment, Execute, Object, Error,
};

enum DX_MEMORY {
	Default, Win32, Syscall,
};

typedef struct _hash_map {
	DWORD   Name;
	LPVOID  Address;
} HASH_MAP, *PHASH_MAP;

typedef struct _object_map {
	PBYTE   Address;
	SIZE_T  Size;
} OBJECT_MAP, *POBJECT_MAP;

typedef struct _buffer {
    LPVOID Buffer;
    UINT32 Length;
} BUFFER, *PBUFFER;

typedef struct _mbs_buffer {
	LPSTR    Buffer;
	ULONG    Length;
	ULONG    Capacity;
} MBS_BUFFER, *PMBS_BUFFER;

typedef struct _wcs_buffer {
	LPWSTR   Buffer;
	ULONG    Length;
	ULONG    Capacity;
} WCS_BUFFER, *PWCS_BUFFER;

typedef struct _resource {
    LPVOID   Lock;
    HGLOBAL  Global;
    SIZE_T   Size;
} RESOURCE, *PRESOURCE;

typedef struct _threadless {
    PCHAR       TargetProc;
    PCHAR       TargetMod;
    PCHAR       TargetExp;
    POBJECT_MAP Loader;
    POBJECT_MAP Opcode;
} THREADLESS, *PTHREADLESS;

typedef struct _veh_writer {
    LPVOID   Target;
    PWCHAR   ModName;
    PCHAR    Signature;
    PCHAR    Mask;
} VEH_WRITER, *PVEH_WRITER;

typedef struct _coff_symbol {
	union {
		CHAR    Name[8];
		UINT32  Value[2];
	} First;

	UINT32 Value;
	UINT16 SectionNumber;
	UINT16 Type;
	UINT8  StorageClass;
	UINT8  NumberOfAuxSymbols;
} COFF_SYMBOL, *PCOFF_SYMBOL;

typedef struct _coff_params {
	PCHAR    	Entrypoint;
	DWORD    	nEntrypoint;
	PVOID    	Data;
	PVOID    	Args;
	SIZE_T   	nData;
	SIZE_T   	nArgs;
	UINT32   	TaskId;
	UINT32   	BofId;
    BOOL     	bCache;
	_coff_params *Next;
}COFF_PARAMS, *PCOFF_PARAMS;

typedef struct _inject_context {
	HANDLE  Process;
	DWORD   Tid;
	DWORD   Pid;
	HANDLE  Thread;
	SHORT   Arch;
	BOOL    bStdout;
	BOOL    SuspendAwake;
	LPVOID  Parameter;
	UINT32  nParameter;
	SHORT   Technique;
} INJECT_CONTEXT, *PINJECT_CONTEXT;

typedef struct _reloc {
	UINT32  VirtualAddress;
	UINT32  SymbolTableIndex;
	UINT16  Type;
} RELOC, *PRELOC;

typedef struct _executable {
	BOOL                    Link;
	BOOL                    Success;
	PBYTE                   Data;
	LPVOID                  Text;
	SIZE_T                  Size;

	LPWSTR                  LocalName;
	LPWSTR                  CrackedName;
	SIZE_T                  DataSize;
	UINT32                  TaskId;

	PRELOC                  Reloc;
	IMAGE_NT_HEADERS        *NtHead;
	IMAGE_SECTION_HEADER    *SxnHead;
	IMAGE_EXPORT_DIRECTORY  *Exports;
	PCOFF_SYMBOL            Symbols;
	POBJECT_MAP             FnMap;
	POBJECT_MAP             SecMap;
	INT                     nReloc;
	INT                     nMapping;

	HANDLE                  Heap;
	HANDLE                  Handle;
	HANDLE                  Thread;
	PPS_ATTRIBUTE_LIST      Attrs;
	PRTL_USER_PROCESS_PARAMETERS Params;
	PS_CREATE_INFO          CreateInfo;

	_executable *Next;
} EXECUTABLE, *PEXECUTABLE;

typedef struct _request {
    HINTERNET ConnHandle;
    HINTERNET ReqHandle;
    LPWSTR    Endpoint;
} REQUEST, *PREQUEST;

typedef struct _proxy {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG    Config;
    WINHTTP_AUTOPROXY_OPTIONS               Autoproxy;
    WINHTTP_PROXY_INFO                      ProxyInfo;

	LPWSTR Address;
	LPWSTR Username;
	LPWSTR Password;
} PROXY, *PPROXY;

typedef struct _http {
	HINTERNET    Handle;
	LPWSTR       Useragent;
	LPWSTR       Method;
	LPWSTR       Address;
	INT          Port;
	LPCWSTR      Accept;
	ULONG        Access;
	ULONG        Flags;
	INT          nEndpoints;
	LPWSTR       *Endpoints;
	LPWSTR       *Headers;
	PROXY        *Proxy;
} HTTP, *PHTTP;

typedef struct _token {
	HANDLE  Handle;
	LPWSTR  DomainUser;
	DWORD   Pid;
	SHORT   Type;

	LPWSTR   Username;
	LPWSTR   Password;
	LPWSTR   Domain;

	_token* Next;
} TOKEN, *PTOKEN;

typedef struct _pipe {
	DWORD    PeerId;
	HANDLE   PipeHandle;
	LPWSTR   PipeName;
	_pipe  *Next;
} PIPE, *PPIPE;

typedef void (*OBJ_ENTRY)(char* args, uint32_t size);

struct LdrpVectorHandlerEntry {
    LdrpVectorHandlerEntry *Flink;
    LdrpVectorHandlerEntry *Blink;
    uint64_t               Unknown1;
    uint64_t               Unknown2;
    PVECTORED_EXCEPTION_HANDLER Handler;
};

struct LdrpVectorHandlerList {
    LdrpVectorHandlerEntry *First;
    LdrpVectorHandlerEntry *Last;
    SRWLOCK 				Lock;
};

typedef struct _parser {
    LPVOID  Handle;
    LPVOID  Buffer;
    ULONG   Length;
} PARSER, *PPARSER;

typedef struct _packet {
    BYTE    	TransportType;
    ULONG   	PeerId;
    ULONG   	TaskId;
    ULONG   	MsgType;
    ULONG   	MsgLength;
    PBYTE   	MsgData;
    BOOL    	Ready;
	BOOL 		Remove;
    _packet  	*Next;
} PACKET, *PPACKET;

struct _hexane {
	PTEB          	Teb;
	LPVOID        	Heap;
	DWORD         	nThreads;
	PCOFF_PARAMS  	DataCache;
	PPIPE    		PeerCache;
	PPACKET 		MessageCache;

	struct {
		PBYTE   SessionKey;
		UINT32  WorkingHours;
		UINT64  Killdate;
		LPSTR   Hostname;
		ULONG   Sleeptime;
		ULONG   Jitter;
		ULONG   Hours;
		DWORD 	PeerId
	} Config;

	struct {
		WORD   Arch;
		ULONG  Ppid;
		ULONG  Pid;
		ULONG  Tid;
		ULONG  Version;
		ULONG  CurrentTaskId;
		UINT32 Retries;
		BOOL   CheckIn;
	} Session;

	struct {
		PHTTP 	Http;
        LPWSTR  EgressName;
        HANDLE  EgressHandle;
		LPSTR   Domain;
		LPVOID  EnvProxy;
		SIZE_T  nEnvProxy;
		BOOL    bSSL;
		BOOL    bProxy;
		BOOL    bEnvProxy;
		BOOL    bCheck;
	} Transport;

	struct {
		// Validation / Utility
		DTYPE(IsBadReadPtr);

		// File I/O
		DTYPE(CreateFileW);
		DTYPE(GetFileAttributesW);
		DTYPE(FindFirstFileA);
		DTYPE(FindFirstFileW);
		DTYPE(FindNextFileA);
		DTYPE(FindNextFileW);
		DTYPE(FindClose);
		DTYPE(GetFileSize);
		DTYPE(ReadFile);
		DTYPE(WriteFile);

		// Time and Date
		DTYPE(FileTimeToSystemTime);
		DTYPE(SystemTimeToTzSpecificLocalTime);
		DTYPE(GetSystemTimeAsFileTime);
		DTYPE(GetLocalTime);
		DTYPE(GetCurrentDirectoryA);

		// Path Operations
		DTYPE(PathFindFileNameW);

		// Named Pipes
		DTYPE(CallNamedPipeW);
		DTYPE(CreateNamedPipeW);
		DTYPE(WaitNamedPipeW);
		DTYPE(SetNamedPipeHandleState);
		DTYPE(ConnectNamedPipe);
		DTYPE(TransactNamedPipe);
		DTYPE(DisconnectNamedPipe);
		DTYPE(PeekNamedPipe);

		// HTTP / Networking
		DTYPE(WinHttpOpen);
		DTYPE(WinHttpConnect);
		DTYPE(WinHttpOpenRequest);
		DTYPE(WinHttpAddRequestHeaders);
		DTYPE(WinHttpSetOption);
		DTYPE(WinHttpGetProxyForUrl);
		DTYPE(WinHttpGetIEProxyConfigForCurrentUser);
		DTYPE(WinHttpSendRequest);
		DTYPE(WinHttpReceiveResponse);
		DTYPE(WinHttpReadData);
		DTYPE(WinHttpQueryHeaders);
		DTYPE(WinHttpQueryDataAvailable);
		DTYPE(WinHttpCloseHandle);
		DTYPE(GetAdaptersInfo);

		// Security / ACL / Tokens
		DTYPE(LookupAccountSidW);
		DTYPE(LookupPrivilegeValueA);
		DTYPE(ImpersonateLoggedOnUser);
		DTYPE(AdjustTokenPrivileges);
		DTYPE(AddMandatoryAce);
		DTYPE(SetEntriesInAclA);
		DTYPE(AllocateAndInitializeSid);
		DTYPE(InitializeSecurityDescriptor);
		DTYPE(SetSecurityDescriptorDacl);
		DTYPE(SetSecurityDescriptorSacl);
		DTYPE(InitializeAcl);
		DTYPE(FreeSid);
		NtOpenProcessToken_t NtOpenProcessToken;
		NtOpenThreadToken_t NtOpenThreadToken;
		NtDuplicateToken_t NtDuplicateToken;
		NtQueryInformationToken_t NtQueryInformationToken;

		// Process Management
		NtOpenProcess_t NtOpenProcess;
		NtCreateUserProcess_t NtCreateUserProcess;
		NtTerminateProcess_t NtTerminateProcess;
		RtlCreateProcessParametersEx_t RtlCreateProcessParametersEx;
		RtlDestroyProcessParameters_t RtlDestroyProcessParameters;
		NtDuplicateObject_t NtDuplicateObject;
		NtQueryInformationProcess_t NtQueryInformationProcess;
		DTYPE(GetProcessId);
		DTYPE(GetCurrentProcessId);
		DTYPE(IsWow64Process);

		// Threading / APCs
		NtCreateThreadEx_t NtCreateThreadEx;
		NtOpenThread_t NtOpenThread;
		NtTerminateThread_t NtTerminateThread;
		NtResumeThread_t NtResumeThread;
		NtGetContextThread_t NtGetContextThread;
		NtSetContextThread_t NtSetContextThread;
		NtSetInformationThread_t NtSetInformationThread;
		NtQueueApcThread_t NtQueueApcThread;
		NtAlertResumeThread_t NtAlertResumeThread;
		NtWaitForSingleObject_t NtWaitForSingleObject;
		NtSignalAndWaitForSingleObject_t NtSignalAndWaitForSingleObject;
		NtContinue_t NtContinue;
		NtTestAlert_t NtTestAlert;
		NtDelayExecution_t NtDelayExecution;
		NtCreateEvent_t NtCreateEvent;

		// Threadpool
		TpAllocWork_t TpAllocWork;
		TpPostWork_t TpPostWork;
		TpReleaseWork_t TpReleaseWork;

		// Memory / Virtual Memory
		NtFreeVirtualMemory_t NtFreeVirtualMemory;
		NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
		NtProtectVirtualMemory_t NtProtectVirtualMemory;
		NtReadVirtualMemory_t NtReadVirtualMemory;
		NtWriteVirtualMemory_t NtWriteVirtualMemory;
		NtQueryVirtualMemory_t NtQueryVirtualMemory;
		NtCreateSection_t NtCreateSection;
		NtMapViewOfSection_t NtMapViewOfSection;
		NtUnmapViewOfSection_t NtUnmapViewOfSection;
		DTYPE(FlushInstructionCache);
		SetProcessValidCallTargets_t SetProcessValidCallTargets;

		// Heap Management
		RtlCreateHeap_t RtlCreateHeap;
		RtlAllocateHeap_t RtlAllocateHeap;
		RtlReAllocateHeap_t RtlReAllocateHeap;
		RtlFreeHeap_t RtlFreeHeap;
		RtlDestroyHeap_t RtlDestroyHeap;
		RtlRbInsertNodeEx_t RtlRbInsertNodeEx;

		// Exception Handling
		RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler;
		RtlRemoveVectoredExceptionHandler_t RtlRemoveVectoredExceptionHandler;

		// Module / Library
		DTYPE(GetProcAddress);
		DTYPE(GetModuleHandleA);
		DTYPE(LoadLibraryA);
		DTYPE(FreeLibrary);

		// Registry
		DTYPE(RegOpenKeyExA);
		DTYPE(RegCreateKeyExA);
		DTYPE(RegSetValueExA);
		DTYPE(RegCloseKey);

		// System Info
		DTYPE(GetUserNameA);
		DTYPE(GetComputerNameExA);
		DTYPE(GlobalMemoryStatusEx);
		RtlGetVersion_t RtlGetVersion;
		NtQuerySystemInformation_t NtQuerySystemInformation;
		NtQuerySystemTime_t NtQuerySystemTime;

		// Toolhelp Snapshots
		DTYPE(CreateToolhelp32Snapshot);
		DTYPE(Process32First);
		DTYPE(Process32Next);
		DTYPE(Module32First);
		DTYPE(Module32Next);

		// CLR Hosting
		CLRCreateInstance_t CLRCreateInstance;

		// Crypto
		DTYPE(CryptStringToBinaryA);
		DTYPE(CryptBinaryToStringA);

		// Resources
		DTYPE(FindResourceA);
		DTYPE(LoadResource);
		DTYPE(LockResource);
		DTYPE(SizeofResource);
		DTYPE(FreeResource);

		// Random, Unicode, Misc
		RtlInitUnicodeString_t RtlInitUnicodeString;
		RtlHashUnicodeString_t RtlHashUnicodeString;
		RtlRandomEx_t RtlRandomEx;
		DTYPE(SleepEx);

		// Native API Finalizer
		NtClose_t NtClose;
	} Win32;
};

DATA_SXN HEXANE *Ctx = nullptr;
#endif
