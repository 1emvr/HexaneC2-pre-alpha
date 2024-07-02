#ifndef _HEXANE_STREAM_HPP
#define _HEXANE_STREAM_HPP
#include <include/monolith.hpp>
#include <include/cruntime.hpp>
#include <include/memory.hpp>

namespace Stream {

	FUNCTION UINT32 ExtractU32 (PBYTE Buffer);
	FUNCTION VOID PackInt64(PBYTE buffer, UINT64 value);
	FUNCTION VOID PackInt32(PBYTE buffer, UINT32 value);

    FUNCTION PSTREAM CreateStream(VOID);
	FUNCTION PSTREAM CreateStreamWithHeaders(DWORD MsgType);
	FUNCTION VOID DestroyStream(PSTREAM stream);
	FUNCTION VOID PackByte (PSTREAM stream, BYTE data);
	FUNCTION VOID PackDword64(PSTREAM stream, DWORD64 data);
	FUNCTION VOID PackDword(PSTREAM stream, DWORD data);
	FUNCTION VOID PackBool(PSTREAM stream, BOOL data);
	FUNCTION VOID PackBytes(PSTREAM stream, PBYTE data, SIZE_T size);
	FUNCTION VOID PackPointer(PSTREAM stream, PVOID pointer);
	FUNCTION VOID PackString(PSTREAM stream, PCHAR data);
	FUNCTION VOID PackWString(PSTREAM stream, PWCHAR data);
}
namespace Parser {

	FUNCTION VOID ParserStrcpy(PPARSER Parser, LPSTR *Dst);
	FUNCTION VOID ParserWcscpy(PPARSER Parser, LPWSTR *Dst);
	FUNCTION VOID ParserMemcpy(PPARSER Parser, PBYTE *Dst);
	FUNCTION VOID CreateParser(PPARSER Parser, PBYTE buffer, DWORD size);
	FUNCTION VOID DestroyParser(PPARSER Parser);
	FUNCTION BYTE UnpackByte(PPARSER parser);
	FUNCTION SHORT UnpackShort(PPARSER parser);
	FUNCTION DWORD UnpackDword(PPARSER parser);
	FUNCTION DWORD64 UnpackDword64(PPARSER parser);
	FUNCTION BOOL UnpackBool(PPARSER parser);
	FUNCTION PBYTE UnpackBytes(PPARSER parser, PDWORD cbOut);
	FUNCTION LPSTR UnpackString(PPARSER parser, PDWORD cbOut);
	FUNCTION LPWSTR UnpackWString(PPARSER parser, PDWORD cbOut);
}
#endif //_HEXANE_STREAM_HPP