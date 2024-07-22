#ifndef HEXANE_CORELIB_STREAM_HPP
#define HEXANE_CORELIB_STREAM_HPP
#include "core/monolith.hpp"
#include "core/corelib.hpp"

namespace Stream {

	FUNCTION UINT32 ExtractU32 (BYTE CONST *Buffer);
	FUNCTION VOID PackInt64(PBYTE buffer, UINT64 value);
	FUNCTION VOID PackInt32(PBYTE buffer, UINT32 value);

    FUNCTION PSTREAM CreateStream(VOID);
	FUNCTION PSTREAM CreateStreamWithHeaders(ULONG MsgType);
	FUNCTION VOID DestroyStream(PSTREAM stream);
	FUNCTION VOID PackByte (PSTREAM stream, BYTE data);
	FUNCTION VOID PackDword64(PSTREAM stream, ULONG64 data);
	FUNCTION VOID PackDword(PSTREAM stream, ULONG data);
	FUNCTION VOID PackBytes(PSTREAM stream, PBYTE data, SIZE_T size);
	FUNCTION VOID PackPointer(PSTREAM stream, PVOID pointer);
	FUNCTION VOID PackString(PSTREAM stream, PCHAR data);
	FUNCTION VOID PackWString(PSTREAM stream, PWCHAR data);
}
#endif //HEXANE_CORELIB_STREAM_HPP