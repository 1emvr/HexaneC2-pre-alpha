#include <core/include/stream.hpp>
namespace Stream {
    // TODO: add fin flag?

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
        PackUint32(stream, cmd_id);

        return stream;
    }

    _stream * CreateStreamWithHeaders(uint32_t type) {
        HEXANE;

        _stream *stream = CreateStream();

        PackUint32(stream, ctx->session.peer_id);
        PackUint32(stream, ctx->session.current_taskid);
        PackUint32(stream, type);

        return stream;
    }

    _stream* CreateStream () {
        HEXANE;

        _stream *stream = { };

        x_assert(stream = (_stream*) Malloc(sizeof(_stream)));
        x_assert(stream->buffer = B_PTR(Malloc(sizeof(uint8_t))));

        stream->length 	= 0;
        stream->next 	= nullptr;

        defer:
        return stream;
    }

    VOID DestroyStream (_stream *stream) {
        HEXANE;

        if (stream) {
            if (stream->buffer) {

                MemSet(stream->buffer, 0, stream->length);
                Free(stream->buffer);

                stream->buffer   = nullptr;
                stream->peer_id  = 0;
                stream->task_id  = 0;
                stream->type     = 0;
                stream->length   = 0;
            }

            Free(stream);
        }
    }

    VOID PackByte (_stream *stream, uint8_t data) {
        HEXANE;

        if (stream) {
            stream->buffer = B_PTR(Realloc(stream->buffer, stream->length + sizeof(uint8_t)));

            MemCopy(B_PTR(stream->buffer) + stream->length, &data, sizeof(uint8_t));
            stream->length += sizeof(uint8_t);
        }
    }

    VOID PackUint64 (_stream *stream, uint64_t data) {
        HEXANE;

        if (stream) {
            stream->buffer = B_PTR(Realloc(stream->buffer, stream->length + sizeof(uint64_t)));

            PackInt64(B_PTR(stream->buffer) + stream->length, data);
            stream->length += sizeof(uint64_t);
        }
    }

    VOID PackUint32 (_stream *stream, uint32_t data) {
        HEXANE;

        if (stream) {
            stream->buffer = B_PTR(Realloc(stream->buffer, stream->length + sizeof(uint32_t)));

            PackInt32(B_PTR(stream->buffer) + stream->length, data);
            stream->length += sizeof(uint32_t);
        }
    }

    VOID PackBytes (_stream *stream, uint8_t *data, size_t size) {
        HEXANE;

        if (stream) {
            if (size) {
                PackUint32(stream, (uint32_t) size);
                stream->buffer = B_PTR(Realloc(stream->buffer, stream->length + size));

                MemCopy(B_PTR(stream->buffer) + stream->length, data, size);
                stream->length += size;
            }
            else {
                PackUint32(stream, 0);
            }
        }
    }

    VOID PackPointer (_stream *stream, void *pointer) {
#ifdef _M_X64
        PackUint64(stream, (uintptr_t)pointer);
#elif _M_IX86
        PackUint32(stream, (uintptr_t)pointer);
#endif
    }

   VOID PackString (_stream *stream, char* data) {
        PackBytes(stream, (uint8_t*) data, MbsLength(data));
    }

    VOID PackWString (_stream *stream, wchar_t* data) {
        PackBytes(stream, (uint8_t*) data, WcsLength(data));
    }
}
