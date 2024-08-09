#ifndef HEXANE_MONOLITH_HPP
#define HEXANE_MONOLITH_HPP
#include <core/ntimports.hpp>
#include <core/dotnet.hpp>

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

#define FUNCTION								TXT_SECTION(B)
#define PROTOTYPE(x)                            __typeof__(x) *x
#define DLL_EXPORT 								__declspec(dllexport)
#define TXT_SECTION(x) 							__attribute__((used, section(".text$" #x "")))
#define DATA_SECTION  							__attribute__((used, section(".data")))
#define RDATA_SECTION  							__attribute__((used, section(".rdata")))
#define WEAK									__attribute__((weak))

#define LocalHeap								NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap
#define ntstatus 								Ctx->Teb->LastErrorValue

#define PS_ATTR_LIST_SIZE(n)					(sizeof(PS_ATTRIBUTE_LIST) + (sizeof(PS_ATTRIBUTE) * (n - 1)))
#define MODULE_NAME(mod)						(mod->BaseDllName.Buffer)

#define PEB_POINTER64							(R_CAST(PPEB, __readgsqword(0x60)))
#define PEB_POINTER32							(R_CAST(PPEB, __readfsdword(0x30)))
#define REG_PEB32(ctx) 						    (R_CAST(LPVOID, R_CAST(ULONG_PTR, ctx.Ebx) + 0x8))
#define REG_PEB64(ctx) 						    (R_CAST(LPVOID, R_CAST(ULONG_PTR, ctx.Rdx) + 0x10))

#define IMAGE_DOS_HEADER(base)                	(R_CAST(PIMAGE_DOS_HEADER, base))
#define IMAGE_NT_HEADERS(base, dos)				(R_CAST(PIMAGE_NT_HEADERS, B_PTR(base) + dos->e_lfanew))
#define IMAGE_EXPORT_DIRECTORY(dos, nt)	    	(R_CAST(PIMAGE_EXPORT_DIRECTORY, (U_PTR(dos) + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)))

#define MODULE_ENTRY(next)                      (R_CAST(PLDR_MODULE, (B_PTR(next) - sizeof(ULONG)* 4)))
#define MODULE_LIST                             (R_CAST(PLIST_ENTRY, &(PEB_POINTER)->Ldr->InMemoryOrderModuleList))
#define BASERELOC_ENTRIES(base, raw, off)		(R_CAST(PBASE_RELOCATION_ENTRY, U_PTR(base) + raw + off))
#define BASERELOC_BLOCK(base, raw, off)		    (R_CAST(PBASE_RELOCATION_BLOCK, U_PTR(base) + raw + off))
#define BASERELOC_COUNT(blk)				    ((blk->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY))

#define RVA(Ty, base, rva)  					(R_CAST(Ty, U_PTR(base) + rva))
#define SECTION_OFFSET(obj, fHead) 			    (R_CAST(LPVOID, R_CAST(ULONG_PTR, obj->lpBase) + fHead->Sections->VirtualAddress))
#define SECTION_DATA(obj, fHead) 				(R_CAST(LPVOID, R_CAST(ULONG_PTR, obj->lpBuffer) + fHead->Sections->PointerToRawData))

#define NtCurrentProcess()              		(R_CAST(HANDLE, -1))
#define NtCurrentThread()               		(R_CAST(HANDLE, S_CAST(LONG_PTR, -2))

#define ARRAY_LEN(ptr) 							sizeof(ptr) / sizeof(ptr[0])
#define DYN_ARRAY_LEN(i, ptr) 					while (TRUE) { if (!ptr[i]) { break; } else { i++; }}
#define DYN_ARRAY_EXPR(i, ptr, x)				while (TRUE) { if (!ptr[i]) { break; } else { {x} i++; }}


#ifdef _M_X64
#define ENTRYPOINT_REG 							Rcx
#define PTR_MASK                                0x7FFFFFFF
#define PEB_POINTER     						PEB_POINTER64
#define DBG_FLAG_OFFSET 						DBG_FLAG_OFFSET64
#define IMAGE_OPT_MAGIC 						IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define MACHINE_ARCH    						IMAGE_FILE_MACHINE_AMD64
#elif _M_IX86
#define ENTRYPOINT_REG 							Eax
#define PTR_MASK                                0x7FFF
#define PEB_POINTER     						PEB_POINTER32
#define DBG_FLAG_OFFSET 						DBG_FLAG_OFFSET32
#define IMAGE_OPT_MAGIC 						IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define MACHINE_ARCH    						IMAGE_FILE_MACHINE_I386
#endif

#define HEAP_NO_COMMIT							0, 0, 0, 0, 0
#define DESKTOP_ENVIRONMENT_NULL				0, 0, 0, 0, 0, 0, 0
#define SMB_SID_SINGLE_WORLD_SUBAUTHORITY		SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0
#define SMB_RID_SINGLE_MANDATORY_LOW			SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0
#define PROCESS_CREATE_ALL_ACCESS_SUSPEND		PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, nullptr, nullptr, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED

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

#define DEFAULT_SECTION_SIZE						0x00001000
#define DEFAULT_BUFFLEN								0x00000400

#ifdef TRANSPORT_PIPE
#define MESSAGE_MAX PIPE_BUFFER_MAX
#else
#define MESSAGE_MAX HTTP_REQUEST_MAX
#endif

typedef NTSTATUS(WINAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t)(HANDLE processHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(WINAPI* NtProtectVirtualMemory_t)(HANDLE processHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(HANDLE processHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
typedef NTSTATUS(WINAPI* NtFreeVirtualMemory_t)(HANDLE processHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS(WINAPI* NtCreateSection_t)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS(WINAPI* NtMapViewOfSection_t)(HANDLE SectionHandle, HANDLE processHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS(WINAPI* NtUnmapViewOfSection_t) (HANDLE processHandle, PVOID BaseAddress);

typedef PVOID(WINAPI* RtlCreateHeap_t)(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PRTL_HEAP_PARAMETERS Parameters);
typedef PVOID(WINAPI* RtlAllocateHeap_t)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
typedef PVOID(WINAPI* RtlReAllocateHeap_t)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);
typedef PVOID(WINAPI* RtlDestroyHeap_t)(PVOID HeapHandle);
typedef LOGICAL(WINAPI* RtlFreeHeap_t)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);

typedef NTSTATUS(WINAPI* NtOpenProcess_t)(PHANDLE hProcess, ACCESS_MASK dwDesiredAccess, POBJECT_ATTRIBUTES objectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(WINAPI* NtTerminateProcess_t)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(WINAPI* NtOpenProcessToken_t)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
typedef NTSTATUS(WINAPI* NtQueryInformationToken_t)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* NtCreateUserProcess_t)(PHANDLE processHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParams, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST ProcessAttributeList);
typedef NTSTATUS(WINAPI* RtlCreateProcessParametersEx_t)(PRTL_USER_PROCESS_PARAMETERS* params, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI* RtlDestroyProcessParameters_t)(PRTL_USER_PROCESS_PARAMETERS procParams);
typedef NTSTATUS (WINAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW lpVersionInformation);
typedef ULONG (WINAPI* RtlRandomEx_t)(PULONG Seed);

typedef NTSTATUS(WINAPI* NtGetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(WINAPI* NtSetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(WINAPI* NtResumeThread_t)(HANDLE hThr, PULONG PrviousSuspendCount);
typedef NTSTATUS(WINAPI* NtWaitForSingleObject_t)(HANDLE Handle, BOOLEAN Alertable, ULONG Timeout);
typedef NTSTATUS(WINAPI* NtClose_t)(HANDLE hObject);
typedef VOID(WINAPI* RtlInitUnicodeString_t)(PUNICODE_STRING Destinationstring, PCWSTR Sourcestring);
typedef NTSTATUS (NTAPI* NtTestAlert_t)(VOID);
typedef NTSTATUS (WINAPI* TpAllocWork_t)(PTP_WORK* ptpWork, PTP_WORK_CALLBACK callback, PVOID optArgs, PTP_CALLBACK_ENVIRON cbEnviron);
typedef VOID (WINAPI* TpPostWork_t)(PTP_WORK ptpWork);
typedef VOID (WINAPI* TpReleaseWork_t)(PTP_WORK ptpWork);

enum MessageType {
	TypeCheckin     = 0x7FFFFFFF,
	TypeTasking     = 0x7FFFFFFE,
	TypeResponse    = 0x7FFFFFFD,
	TypeSegment     = 0x7FFFFFFC,
    TypeExecute     = 0x7FFFFFFB,
};

typedef struct {
	LPVOID							lpBuffer;
	LPVOID							lpHeap;
	LPVOID							lpBase;

	SIZE_T 							tImage;
	ULONG							dwSize;
	ULONG							dwRead;
	ULONG 							dwData;
	ULONG 							dwHeads;
	WORD 							nSections;
	LARGE_INTEGER					lnSections;

	PIMAGE_DOS_HEADER				dosHead;
	PIMAGE_NT_HEADERS				ntHead;
	IMAGE_DATA_DIRECTORY 			Relocs;
	PIMAGE_SECTION_HEADER			Sections;

	HANDLE							pHandle;
	HANDLE							pThread;

	PS_CREATE_INFO					Create;
	PPS_ATTRIBUTE_LIST				Attrs;
	PRTL_USER_PROCESS_PARAMETERS	Params;
	UNICODE_STRING					Unicode;
	BOOL                      		Allocated;

} IMAGE, *PIMAGE;


typedef struct {
	LPSTR 	Buffer;
	ULONG 	Length;
} A_BUFFER;

typedef struct {
	LPWSTR 	Buffer;
	ULONG 	Length;
} W_BUFFER;

typedef struct {
    LPVOID  ResLock;
    HGLOBAL hGlobal;
    SIZE_T  Size;
} RSRC, *PRSRC;


typedef struct {
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
} HTTP_CONTEXT, *PHTTP_CONTEXT;


typedef struct stream {
	ULONG   PeerId;
	ULONG   TaskId;
	ULONG   MsgType;
	ULONG	Length;
	LPVOID	Buffer;
	BOOL 	Ready;
	stream  *Next;
} STREAM, *PSTREAM;


typedef struct {
	LPVOID 	Handle;
    LPVOID  Buffer;
	ULONG 	Length;
	BOOL 	LE;
} PARSER, *PPARSER;


typedef struct {
	PSID					Sid;
	PSID					SidLow;
	PACL					pAcl;
	PSECURITY_DESCRIPTOR	SecDesc;
} SMB_PIPE_SEC_ATTR, *PSMB_PIPE_SEC_ATTR;


typedef VOID(*CmdSignature)(PPARSER Args);
typedef struct {
	int32_t         Id;
	CmdSignature    Function;
} COMMAND_MAP;


typedef struct {

	LPVOID 	Heap;
	PTEB 	Teb;
	BOOL	Root;
    BOOL    LE;

	struct {
		UINT_PTR    Address;
		ULONG	    Size;
	} Base;

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
		LPSTR	ImplantUuid;
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
		INT 		Retry;
		BOOL	    Checkin;
		ULONG	    Ppid;
		ULONG	    Pid;
		ULONG	    Tid;
		WORD	    Architecture;
		ULONG	    OSVersion;
		ULONG	    CurrentTaskId;
        ULONG		PeerId;
	} Session;

	struct {
		BOOL  	    	bSSL;
		BOOL	    	bProxy;
		BOOL	    	bEnvProxy;
		BOOL	    	bEnvProxyCheck;
		LPVOID	    	EnvProxy;
		SIZE_T	    	EnvProxyLen;
		LPSTR 			Domain;
		PHTTP_CONTEXT 	http;
        PSTREAM        	OutboundQueue;
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
		PROTOTYPE(LoadLibraryA);
		PROTOTYPE(FreeLibrary);
		PROTOTYPE(GetProcessHeap);
		PROTOTYPE(GetProcAddress);
		PROTOTYPE(GetModuleHandleA);

		PROTOTYPE(IsWow64Process);
        PROTOTYPE(OpenProcess);
		PROTOTYPE(CreateToolhelp32Snapshot);
		PROTOTYPE(Process32First);
		PROTOTYPE(Process32Next);
        PROTOTYPE(Module32First);
        PROTOTYPE(Module32Next);
		PROTOTYPE(GetCurrentProcessId);
		PROTOTYPE(GetProcessId);

		PROTOTYPE(GlobalMemoryStatusEx);
		PROTOTYPE(GetComputerNameExA);
		PROTOTYPE(SetLastError);
		PROTOTYPE(GetLastError);

		PROTOTYPE(ReadFile);
		PROTOTYPE(WriteFile);
		PROTOTYPE(CreateFileW);
		PROTOTYPE(GetFileSizeEx);
		PROTOTYPE(GetFullPathNameA);
		PROTOTYPE(FindFirstFileA);
		PROTOTYPE(FindClose);
		PROTOTYPE(FindNextFileA);
		PROTOTYPE(GetCurrentDirectoryA);
		PROTOTYPE(FileTimeToSystemTime);
		PROTOTYPE(SystemTimeToTzSpecificLocalTime);
		PROTOTYPE(GetLocalTime);
		PROTOTYPE(GetSystemTimeAsFileTime);

		PROTOTYPE(FormatMessageA);
		PROTOTYPE(CreateRemoteThread);
		PROTOTYPE(CreateThread);
		PROTOTYPE(QueueUserAPC);
		PROTOTYPE(GetThreadLocale);
		PROTOTYPE(SleepEx);

		PROTOTYPE(WinHttpOpen);
		PROTOTYPE(WinHttpConnect);
		PROTOTYPE(WinHttpOpenRequest);
		PROTOTYPE(WinHttpAddRequestHeaders);
		PROTOTYPE(WinHttpSetOption);
		PROTOTYPE(WinHttpGetProxyForUrl);
		PROTOTYPE(WinHttpGetIEProxyConfigForCurrentUser);
		PROTOTYPE(WinHttpSendRequest);
		PROTOTYPE(WinHttpReceiveResponse);
		PROTOTYPE(WinHttpReadData);
		PROTOTYPE(WinHttpQueryHeaders);
		PROTOTYPE(WinHttpQueryDataAvailable);
		PROTOTYPE(WinHttpCloseHandle);
		PROTOTYPE(GetAdaptersInfo);

		PROTOTYPE(CryptStringToBinaryA);
		PROTOTYPE(CryptBinaryToStringA);
		PROTOTYPE(FindResourceA);
		PROTOTYPE(LoadResource);
		PROTOTYPE(LockResource);
		PROTOTYPE(SizeofResource);
		PROTOTYPE(FreeResource);

		PROTOTYPE(CallNamedPipeW);
		PROTOTYPE(CreateNamedPipeW);
		PROTOTYPE(WaitNamedPipeW);
		PROTOTYPE(SetNamedPipeHandleState);
		PROTOTYPE(ConnectNamedPipe);
		PROTOTYPE(TransactNamedPipe);
		PROTOTYPE(DisconnectNamedPipe);
		PROTOTYPE(PeekNamedPipe);

		PROTOTYPE(GetUserNameA);
		PROTOTYPE(LookupAccountSidW);
		PROTOTYPE(LookupPrivilegeValueA);
		PROTOTYPE(SetEntriesInAclA);
		PROTOTYPE(AllocateAndInitializeSid);
		PROTOTYPE(AddMandatoryAce);
		PROTOTYPE(InitializeSecurityDescriptor);
		PROTOTYPE(SetSecurityDescriptorDacl);
		PROTOTYPE(SetSecurityDescriptorSacl);
		PROTOTYPE(InitializeAcl);
		PROTOTYPE(FreeSid);

		PROTOTYPE(CLRCreateInstance);
	} win32;

} HEXANE_CTX;

EXTERN_C WEAK ULONG  		__InstanceOffset;
#define GLOBAL_OFFSET       (U_PTR(InstStart()) + U_PTR(&__InstanceOffset))
#define HEXANE 		        HEXANE_CTX* Ctx = R_CAST(HEXANE_CTX*, C_DREF(GLOBAL_OFFSET));

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


#define FPTR(Fn, mod, sym) 	\
	Fn = (__typeof__(Fn)) Memory::LdrGetSymbolAddress(mod, sym)


#define FPTR2(Fn, mod, sym) \
	Fn = (__typeof__(Fn)) Memory::LdrGetSymbolAddress(Memory::LdrGetModuleAddress(mod), sym)


#define NT_ASSERT(Fn)	\
	Fn; if (NtCurrentTeb()->LastErrorValue != ERROR_SUCCESS) return


#define return_defer(x)	\
	ntstatus = x; goto defer

#endif
