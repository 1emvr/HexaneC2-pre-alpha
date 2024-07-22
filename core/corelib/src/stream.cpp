#include <core/corelib/include/stream.hpp>
namespace Stream {

    VOID PackInt64 (PBYTE buffer, UINT64 value) {

        buffer[7] = value & 0xFF; value >>= 8;
        buffer[6] = value & 0xFF; value >>= 8;
        buffer[5] = value & 0xFF; value >>= 8;
        buffer[4] = value & 0xFF; value >>= 8;
        buffer[3] = value & 0xFF; value >>= 8;
        buffer[2] = value & 0xFF; value >>= 8;
        buffer[1] = value & 0xFF; value >>= 8;
        buffer[0] = value & 0xFF;
    }

    VOID PackInt32 (PBYTE buffer, UINT32 value) {

        buffer[0] = (value >> 24) & 0xFF;
        buffer[1] = (value >> 16) & 0xFF;
        buffer[2] = (value >> 8) & 0xFF;
        buffer[3] = (value) & 0xFF;
    }

    UINT32 ExtractU32 (BYTE CONST *Buffer) {
        return Buffer[0] | (Buffer[1] << 8) | (Buffer[2] << 16) | (Buffer[3] <<24);
    }

    PSTREAM CreateStreamWithHeaders(ULONG MsgType) {

        HEXANE
        PSTREAM Stream = CreateStream();

        PackDword(Stream, Ctx->Session.PeerId);
        PackDword(Stream, Ctx->Session.CurrentTaskId);
        PackDword(Stream, MsgType);

        return Stream;
    }

    PSTREAM CreateStream () {

        HEXANE
        PSTREAM stream = { };

        if (
            !(stream            = SCAST(PSTREAM, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, sizeof(STREAM)))) ||
            !(stream->Buffer    = Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, sizeof(BYTE)))) {
            return_defer(ntstatus);
        }

        stream->Length 	= 0;
        stream->Next 	= nullptr;

        defer:
        return stream;
    }

    VOID DestroyStream (PSTREAM Stream) {

        HEXANE

        if (Stream) {
            if (Stream->Buffer) {

                x_memset(Stream->Buffer, 0, Stream->Length);
                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Stream->Buffer);

                Stream->Buffer  = nullptr;
                Stream->PeerId  = 0;
                Stream->TaskId  = 0;
                Stream->MsgType = 0;
                Stream->Length  = 0;
            }

            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Stream);
        }
    }

    VOID PackByte (PSTREAM stream, BYTE data) {

        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(BYTE));

            x_memcpy(SCAST(PBYTE, stream->Buffer) + stream->Length, &data, sizeof(BYTE));
            stream->Length += sizeof(BYTE);
        }
    }

    VOID PackDword64 (PSTREAM stream, ULONG64 data) {

        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(ULONG64));

            PackInt64(SCAST(PBYTE, stream->Buffer) + stream->Length, data);
            stream->Length += sizeof(UINT64);
        }
    }

    VOID PackDword (PSTREAM stream, ULONG data) {

        HEXANE

        if (stream) {
            stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + sizeof(ULONG));

            PackInt32(SCAST(PBYTE, stream->Buffer) + stream->Length, data);
            stream->Length += sizeof(ULONG);
        }
    }

    VOID PackBytes (PSTREAM stream, PBYTE data, SIZE_T size) {

        HEXANE

        if (stream) {
            if (size) {
                PackDword(stream, size);
                stream->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, stream->Buffer, stream->Length + size);

                x_memcpy(SCAST(PBYTE, stream->Buffer) + stream->Length, data, size);
                stream->Length += size;
            }
        }
    }

    VOID PackPointer (PSTREAM stream, PVOID pointer) {
#ifdef _M_X64
        PackDword64(stream, RCAST(UINT_PTR, pointer));
#elif _M_IX86
        PackDword(stream, SCAST(UINT_PTR, pointer));
#endif
    }

    VOID PackString (PSTREAM stream, LPSTR data) {
        PackBytes(stream, RCAST(PBYTE, data), x_strlen(data));
    }

    VOID PackWString (PSTREAM stream, LPWSTR data) {
        PackBytes(stream, RCAST(PBYTE, data), x_wcslen(data));
    }
}

