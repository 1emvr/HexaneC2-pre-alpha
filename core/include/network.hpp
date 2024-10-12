#ifndef HEXANE_CORELIB_NETWORK_HPP
#define HEXANE_CORELIB_NETWORK_HPP

#define INTERNET_OPEN_TYPE_PROXY                3
#define WINHTTP_FLAG_BYPASS_PROXY_CACHE     	0x00000100
#define WINHTTP_FLAG_SECURE                 	0x00800000

#include <core/corelib.hpp>

namespace Network {
    namespace Http {
        BOOL
        FUNCTION
            CreateProxyContext(PROXY_CONTEXT *proxy_ctx, CONST REQUEST_CONTEXT *req_ctx);

        BOOL
        FUNCTION
            CreateRequestContext(REQUEST_CONTEXT *req_ctx);

        VOID
        FUNCTION
            DestroyProxyContext(PROXY_CONTEXT *proxy_ctx);

        VOID
        FUNCTION
            DestroyRequestContext(REQUEST_CONTEXT *req_ctx);

        VOID
        FUNCTION
            HttpSendRequest(HINTERNET request, STREAM **stream);

        VOID
        FUNCTION
            HttpCallback(STREAM **in, CONST STREAM *out);
    }

    namespace Smb {
        VOID
        FUNCTION
            SmbContextDestroy(PSMB_PIPE_SEC_ATTR SmbSecAttr);

        VOID
        FUNCTION
            SmbContextInit(SMB_PIPE_SEC_ATTR *SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr);

        BOOL
        FUNCTION
            PipeRead(HANDLE handle, STREAM *in);

        BOOL
        FUNCTION
            PipeWrite(HANDLE handle, CONST STREAM *out);

        BOOL
        FUNCTION
            PipeSend (CONST STREAM *out);

        BOOL
        FUNCTION
            PipeReceive(STREAM **in);
    }
}
#endif //HEXANE_CORELIB_NETWORK_HPP
