#include <core/include/stream.hpp>
namespace Stream {

    VOID PackInt64 (uint8_t *buffer, uint64_t value) {

        buffer[7] = value & 0xFF; value >>= 8;
        buffer[6] = value & 0xFF; value >>= 8;
        buffer[5] = value & 0xFF; value >>= 8;
        buffer[4] = value & 0xFF; value >>= 8;
        buffer[3] = value & 0xFF; value >>= 8;
        buffer[2] = value & 0xFF; value >>= 8;
        buffer[1] = value & 0xFF; value >>= 8;
        buffer[0] = value & 0xFF;
    }

    VOID PackInt32 (uint8_t *buffer, uint32_t value) {

        buffer[0] = (value >> 24) & 0xFF;
        buffer[1] = (value >> 16) & 0xFF;
        buffer[2] = (value >> 8) & 0xFF;
        buffer[3] = (value) & 0xFF;
    }

    UINT32 ExtractU32 (uint8_t const *buffer) {
        return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] <<24);
    }

    _stream* CreateTaskResponse(uint32_t cmd_id) {

        auto stream = CreateStreamWithHeaders(TypeResponse);
        Stream::PackDword(stream, cmd_id);
        return stream;
    }

    _stream * CreateStreamWithHeaders(uint32_t msg_type) {

        // response will be [in/out], pid, tid, msg_type, cmd_type, msg_length, msg_buffer
        // tasking will be  [in/out], pid, tid, msg_type
        // checkin will be  [in/out], pid, tid, msg_type

        _stream *stream = CreateStream();
        Stream::PackByte(stream, EGRESS);
        Stream::PackDword(stream, Ctx->session.peer_id);
        Stream::PackDword(stream, Ctx->session.current_taskid);
        Stream::PackDword(stream, msg_type);

        return stream;
    }

    _stream* CreateStream () {

        _stream *stream = { };
        x_assert(stream            = (_stream*) x_malloc(sizeof(_stream)));
        x_assert(stream->buffer    = B_PTR(x_malloc(sizeof(uint8_t))));

        stream->length 	= 0;
        stream->next 	= nullptr;

        defer:
        return stream;
    }

    VOID DestroyStream (_stream *stream) {

        if (stream) {
            if (stream->buffer) {

                x_memset(stream->buffer, 0, stream->length);
                x_free(stream->buffer);

                stream->buffer      = nullptr;
                stream->peer_id     = 0;
                stream->task_id     = 0;
                stream->msg_type    = 0;
                stream->length      = 0;
            }

            x_free(stream);
        }
    }

    VOID PackByte (_stream *stream, uint8_t data) {

        if (stream) {
            stream->buffer = B_PTR(x_realloc(stream->buffer, stream->length + sizeof(uint8_t)));

            x_memcpy(B_PTR(stream->buffer) + stream->length, &data, sizeof(uint8_t));
            stream->length += sizeof(uint8_t);
        }
    }

    VOID PackDword64 (_stream *stream, uint64_t data) {

        if (stream) {
            stream->buffer = B_PTR(x_realloc(stream->buffer, stream->length + sizeof(uint64_t)));

            PackInt64(B_PTR(stream->buffer) + stream->length, data);
            stream->length += sizeof(uint64_t);
        }
    }

    VOID PackDword (_stream *stream, uint32_t data) {

        if (stream) {
            stream->buffer = B_PTR(x_realloc(stream->buffer, stream->length + sizeof(uint32_t)));

            PackInt32(B_PTR(stream->buffer) + stream->length, data);
            stream->length += sizeof(uint32_t);
        }
    }

    VOID PackBytes (_stream *stream, uint8_t *data, size_t size) {

        if (stream) {
            if (size) {
                PackDword(stream, (uint32_t) size);
                stream->buffer = B_PTR(x_realloc(stream->buffer, stream->length + size));

                x_memcpy(B_PTR(stream->buffer) + stream->length, data, size);
                stream->length += size;
            }
        }
    }

    VOID PackPointer (_stream *stream, void *pointer) {
#ifdef _M_X64
        PackDword64(stream, (uintptr_t)pointer);
#elif _M_IX86
        PackDword(stream, (uintptr_t)pointer);
#endif
    }

   VOID PackString (_stream *stream, char* data) {
        PackBytes(stream, (uint8_t*) data, x_strlen(data));
    }

    VOID PackWString (_stream *stream, wchar_t* data) {
        PackBytes(stream, (uint8_t*) data, x_wcslen(data));
    }
}
