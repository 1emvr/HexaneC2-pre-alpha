#ifndef HEXANE_CORELIB_STREAM_HPP
#define HEXANE_CORELIB_STREAM_HPP
#include <core/monolith.hpp>
#include <core/include/stdlib.hpp>

namespace Stream {

	FUNCTION UINT32 ExtractU32 (uint8_t const *buffer);
	FUNCTION VOID PackInt64(uint8_t *buffer, uint64_t value);
	FUNCTION VOID PackInt32(uint8_t *buffer, uint32_t value);

    FUNCTION _stream* CreateStream(void);
	FUNCTION _stream* CreateStreamWithHeaders(uint32_t msg_type);
	FUNCTION VOID DestroyStream(_stream* stream);
	FUNCTION VOID PackByte (_stream* stream, uint8_t data);
	FUNCTION VOID PackDword64(_stream* stream, uint64_t data);
	FUNCTION VOID PackDword(_stream* stream, uint32_t data);
	FUNCTION VOID PackBytes(_stream* stream, uint8_t *data, size_t size);
	FUNCTION VOID PackPointer(_stream* stream, void *pointer);
	FUNCTION VOID PackString(_stream* stream, char *data);
	FUNCTION VOID PackWString(_stream* stream, wchar_t *data);
}
#endif //HEXANE_CORELIB_STREAM_HPP
