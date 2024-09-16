#ifndef HEXANE_CORELIB_NETWORK_HPP
#define HEXANE_CORELIB_NETWORK_HPP

#define INTERNET_OPEN_TYPE_PROXY                3
#define WINHTTP_FLAG_BYPASS_PROXY_CACHE     	0x00000100
#define WINHTTP_FLAG_SECURE                 	0x00800000

#include <core/corelib.hpp>

namespace Network {

    namespace Http {
        FUNCTION VOID HttpSendRequest(HINTERNET request, _stream **stream);
        FUNCTION VOID DestroyRequestContext(const _request_context *req_ctx);
        FUNCTION VOID DestroyProxyContext(const _proxy_context *proxy_ctx);
        FUNCTION BOOL CreateRequestContext(_request_context *req_ctx);
        FUNCTION BOOL CreateProxyContext(_proxy_context *const proxy_ctx, const _request_context *const req_ctx);
        FUNCTION VOID HttpCallback(const _stream *const out, _stream **in);
    }

    namespace Smb {
        FUNCTION VOID SmbContextDestroy(PSMB_PIPE_SEC_ATTR SmbSecAttr);
        FUNCTION BOOL PipeRead(void *const handle, const _stream *in);
        FUNCTION BOOL PipeWrite(void *const handle, const _stream *out);
        FUNCTION BOOL PipeSend (_stream *out);
        FUNCTION BOOL PipeReceive(_stream** in);
    }
}
#endif //HEXANE_CORELIB_NETWORK_HPP
