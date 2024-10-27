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
            CreateProxyContext(PROXY_CONTEXT *proxy_ctx, REQUEST_CONTEXT *req_ctx);

        BOOL
        FUNCTION
            CreateRequestContext(REQUEST_CONTEXT *req_ctx);

        VOID
        FUNCTION
            DestroyProxyContext(PROXY_CONTEXT *proxy_ctx);

        VOID
        FUNCTION
            DestroyRequestContext(REQUEST_CONTEXT *req_ctx);

        BOOL
        FUNCTION
            HttpSendRequest(HINTERNET request, STREAM **stream);

        BOOL
        FUNCTION
            HttpCallback(STREAM **in, STREAM *out);
    }

    namespace Smb {

        typedef struct _smb_pipe_sec_attr{
            PSID	sid;
            PSID	sid_low;
            PACL	p_acl;
            PSECURITY_DESCRIPTOR sec_desc;
        } SMB_PIPE_SEC_ATTR, *PSMB_PIPE_SEC_ATTR;

        BOOL
        FUNCTION
            SmbContextInit(SMB_PIPE_SEC_ATTR *SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr);

        VOID
        FUNCTION
            SmbContextDestroy(PSMB_PIPE_SEC_ATTR SmbSecAttr);

        BOOL
        FUNCTION
            PipeRead(HANDLE handle, STREAM *in);

        BOOL
        FUNCTION
            PipeWrite(HANDLE handle, STREAM *out);

        BOOL
        FUNCTION
            PipeSend (STREAM *out);

        BOOL
        FUNCTION
            PipeReceive(STREAM **in);
    }
}
#endif //HEXANE_CORELIB_NETWORK_HPP
