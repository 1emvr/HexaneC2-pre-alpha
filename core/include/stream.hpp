#ifndef HEXANE_CORELIB_STREAM_HPP
#define HEXANE_CORELIB_STREAM_HPP
#include <core/corelib.hpp>

namespace Stream {
    typedef struct _stream {
        BYTE 		inbound;
        ULONG   	peer_id;
        ULONG   	task_id;
        ULONG   	msg_type;
        ULONG		msg_length;
        PBYTE		buffer;
        BOOL 		ready;
        _stream  	*next;
    } STREAM, *PSTREAM;

	STREAM*
	FUNCTION
		CreateStream();

	STREAM*
	FUNCTION
		CreateTaskResponse(UINT32 cmd_id);

	STREAM*
	FUNCTION
		CreateStreamWithHeaders(UINT32 msg_type);

	FUNCTION
	VOID DestroyStream(STREAM *stream);

	UINT32
	FUNCTION
		ExtractUint32(CONST UINT8 *buffer);

	VOID
	FUNCTION
		PackInt32(UINT8 *buffer, UINT32 data);

	VOID
	FUNCTION
		PackInt64(UINT8 *buffer, UINT64 data);

	VOID
	FUNCTION
		PackUint32(STREAM *stream, UINT32 data);

	VOID
	FUNCTION
		PackUint64(STREAM *stream, UINT64 data);

	VOID
	FUNCTION
		PackByte(STREAM *stream, UINT8 data);

	VOID
	FUNCTION
		PackBytes(STREAM *stream, UINT8 *data, size_t size);

	VOID
	FUNCTION
		PackPointer(STREAM *stream, VOID *pointer);

	VOID
	FUNCTION
		PackString(STREAM *stream, CHAR *data);

	VOID
	FUNCTION
		PackWString(STREAM *stream, WCHAR *data);

}
#endif //HEXANE_CORELIB_STREAM_HPP
