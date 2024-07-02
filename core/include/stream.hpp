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

#endif //_HEXANE_STREAM_HPP